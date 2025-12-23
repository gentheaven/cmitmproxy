#include "proxy.h"

#include "libnet.h"
#include "openssl/ssl3.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/x509v3.h"
#include "openssl/rand.h"

#include "defaults.h"

/*
 * The OpenSSL SNI API only allows to read the indicated server name at the
 * time when we have to provide the server certificate.  OpenSSL does not
 * allow to asynchronously read the indicated server name, wait for some
 * unrelated event to happen, and then later to provide the server certificate
 * to use and continue the handshake.  Therefore we resort to parsing the
 * server name from the ClientHello manually before OpenSSL gets to work on it.

 * This function takes a buffer containing (part of) a ClientHello message as
 * seen on the network as input.

 * Returns:
 *  1  if found SNI
 *  0  if not found

 * References:
 *draft - hickman - netscape - ssl - 00 : The SSL Protocol
 * RFC 6101 : The Secure Sockets Layer(SSL) Protocol Version 3.0
 * RFC 2246 : The TLS Protocol Version 1.0
 * RFC 3546 : Transport Layer Security(TLS) Extensions
 * RFC 4346 : The Transport Layer Security(TLS) Protocol Version 1.1
 * RFC 4366 : Transport Layer Security(TLS) Extensions
 * RFC 5246 : The Transport Layer Security(TLS) Protocol Version 1.2
 * RFC 6066 : Transport Layer Security(TLS) Extensions : Extension Definitions
 */
int ssl_tls_clienthello_parse(const unsigned char* buf, int len, char** servername)
{
	int found_sni = 0;
	//TLS record
	struct TLSRecord* record = (struct TLSRecord*)buf;
	u_int total_len, offset, record_len;

	unsigned char* cur = (unsigned char*)buf;
	total_len = len;
	offset = 0;
	record_len = ntohs(record->length);
	if (record->type != SSL3_RT_HANDSHAKE)
		return 0;

	offset = TLS_RECORD_LEN;
	total_len -= offset;
	cur += offset;

	//parse_handleshake
	struct TLSHandshake* hsHeader = (struct TLSHandshake*)cur;
	offset = TLS_HS_LEN;
	cur += offset;
	total_len -= offset;
	if (hsHeader->msg_type != SSL3_MT_CLIENT_HELLO)
		return 0;

	//clienthello: parse_chello(c2s, cur, total_len);
	struct SSlHello* head = (struct SSlHello*)cur;
	int id_len = head->session_id_len;
	//version: 2B; random: 32B; session id len: 1B
	offset = 2 + 32 + 1 + id_len;
	cur += offset;
	total_len -= offset;

	//CipherSuite length: 2B
	uint16_t cipher_len = PACKET_GET_2(cur);
	offset = cipher_len + 2;
	cur += offset;
	total_len -= offset;

	//CompressionMethod compression_methods<1..2^8-1>;
	id_len = *cur;
	offset = 1 + id_len;
	cur += offset;
	total_len -= offset;

	//extensions, parse_hello_ext(client, cur, total_len);
	cipher_len = PACKET_GET_2(cur);
	offset = 2;
	cur += offset;
	total_len -= offset;
	struct hello_extension* exthead = (struct hello_extension*)cur;

	uint16_t cur_len = 0;
	uint16_t extopt_len;
	uint16_t type;
	char* temp;
	char* name;
	while (1) {
		type = ntohs(exthead->type);
		extopt_len = ntohs(exthead->length);
		//printf("extension_type=%d, length=%d\n", type, extopt_len);
		if (TLSEXT_TYPE_server_name == type) {
			//SNI
			//skip 2 bytes list_length, temp point to struct ext_ServerName
			//name_type: 1B, length: 2B
			temp = cur + cur_len + 6;
			if (*temp == TLSEXT_NAMETYPE_host_name) {
				temp++; //skip type 1B
				int name_len = PACKET_GET_2(temp);
				temp += 2; //skip len 2B
						   //print_char("server_name = ", temp, name_len);
				name = malloc(name_len + 1);
				memcpy(name, temp, name_len);
				name[name_len] = 0;
				*servername = name;
				found_sni = 1;
			}
		} //end TLSEXT_TYPE_server_name == type

		//next extension
		cur_len = cur_len + extopt_len + 4;
		exthead = (struct hello_extension*)(cur + cur_len);
		if (cur_len >= cipher_len)
			break;
	}

	return found_sni;
}

//cert

/*
* in:
*	der = 1: DER format
*	der = 0: PEM format
*
*	public = 1, get pub key, cert
*	public = 0, get private key
*
* call EVP_PKEY_free(pkey); after use it
*/
EVP_PKEY* rsa_get_key_fromfile(const char* filename, int der, int public)
{
	EVP_PKEY* pkey = NULL;

	BIO* bio = NULL;
	if (der)
		bio = BIO_new_file(filename, "rb");
	else
		bio = BIO_new_file(filename, "r");
	if (!bio)
		return NULL;

	if (public) {
		//read from cert, PEM_read_PUBKEY
		X509* cert = NULL;
		if (der)
			cert = d2i_X509_bio(bio, NULL);
		else
			cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (cert) {
			EVP_PKEY* temp = X509_get0_pubkey(cert);
			if (temp)
				pkey = EVP_PKEY_dup(temp);
			X509_free(cert);
		}
	} else {
		//private key, standalone file
		if (der)
			pkey = d2i_PrivateKey_bio(bio, NULL);
		else
			pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	}

	BIO_free(bio);
	return pkey;
}

X509* get_cert(const char* path)
{
	BIO* bio = BIO_new_file(path, "r");
	if (!bio)
		return NULL;
	X509* x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return x;
}

/*
 * Load an Elliptic Curve by name.  If curvename is NULL, a default curve is
 * loaded.
 */
int ssl_ec_nid_by_name(const char* curvename)
{
	if (!curvename)
		curvename = DFLT_CURVE;

	return OBJ_sn2nid(curvename);
}

/*
 * Best effort randomness generator.
 * Not for real life cryptography applications.
 * Returns 0 on success, -1 on failure.
 */
int ssl_rand(void* p, size_t sz)
{
	int rv;
	rv = RAND_bytes((unsigned char*)p, (int)sz);
	if (rv == 1)
		return 0;
	return -1;
}

/*
 * Copy the serial number from src certificate to dst certificate
 * and modify it by a random offset.
 * If reading the serial fails for some reason, generate a new
 * random serial and store it in the dst certificate.
 * Using the same serial is not a good idea since some SSL stacks
 * check for duplicate certificate serials.
 * Returns 0 on success, -1 on error.
 */
int ssl_x509_serial_copyrand(X509* dstcrt, X509* srccrt)
{
	ASN1_INTEGER* srcptr, * dstptr;
	BIGNUM* bnserial;
	unsigned int rand;
	int rv;

	rv = ssl_rand(&rand, sizeof(rand));
	dstptr = X509_get_serialNumber(dstcrt);
	srcptr = X509_get_serialNumber(srccrt);
	if ((rv == -1) || !dstptr || !srcptr)
		return -1;
	bnserial = ASN1_INTEGER_to_BN(srcptr, NULL);
	if (!bnserial) {
		/* random 32-bit serial */
		ASN1_INTEGER_set(dstptr, rand);
	}
	else {
		BN_to_ASN1_INTEGER(bnserial, dstptr);
		BN_free(bnserial);
	}
	return 0;
}

/*
 * Add a X509v3 extension to a certificate and handle errors.
 * Returns -1 on errors, 0 on success.
 */
int ssl_x509_v3ext_add(X509V3_CTX* ctx, X509* crt, char* k, char* v)
{
	X509_EXTENSION* ext;

	if (!(ext = X509V3_EXT_conf(NULL, ctx, k, v))) {
		return -1;
	}
	if (X509_add_ext(crt, ext, -1) != 1) {
		X509_EXTENSION_free(ext);
		return -1;
	}
	X509_EXTENSION_free(ext);
	return 0;
}

/*
 * Copy a X509v3 extension from one certificate to another.
 * If the extension is not present in the original certificate,
 * the extension will not be added to the destination certificate.
 * Returns 1 if ext was copied, 0 if not present in origcrt, -1 on error.
 */
int ssl_x509_v3ext_copy_by_nid(X509* crt, X509* origcrt, int nid)
{
	X509_EXTENSION* ext;
	int pos;

	pos = X509_get_ext_by_NID(origcrt, nid, -1);
	if (pos == -1)
		return 0;
	ext = X509_get_ext(origcrt, pos);
	if (!ext)
		return -1;
	if (X509_add_ext(crt, ext, -1) != 1)
		return -1;
	return 1;
}

/*
 * Returns the appropriate key usage strings for the type of server key.
 * Return value should conceptually be const, but OpenSSL does not use const
 * appropriately.
 */
static char* ssl_key_usage_for_key(EVP_PKEY* key)
{
	switch (EVP_PKEY_type(EVP_PKEY_base_id(key))) {
	case EVP_PKEY_RSA:
		return "keyEncipherment,digitalSignature";

	case EVP_PKEY_DH:
		return "keyAgreement";

	case EVP_PKEY_DSA:
		return "digitalSignature";

	case EVP_PKEY_EC:
		return "digitalSignature,keyAgreement";

	default:
		return "keyEncipherment,keyAgreement,digitalSignature";
	}
}

const EVP_MD* get_cert_md(int type, int nid)
{
	const EVP_MD* md = EVP_sha256();

	switch (type) {
	case EVP_PKEY_RSA:
		switch (nid) {
		case NID_md5WithRSAEncryption:
			md = EVP_md5();
			break;
		case NID_ripemd160WithRSA:
			md = EVP_ripemd160();
			break;
		case NID_sha1WithRSAEncryption:
			md = EVP_sha1();
			break;
		case NID_sha224WithRSAEncryption:
			md = EVP_sha224();
			break;
		case NID_sha256WithRSAEncryption:
			md = EVP_sha256();
			break;
		case NID_sha384WithRSAEncryption:
			md = EVP_sha384();
			break;
		case NID_sha512WithRSAEncryption:
			md = EVP_sha512();
			break;

		default:
			md = EVP_sha256();
			break;
		}
		break;

	case EVP_PKEY_DSA:
		switch (nid) {
		case NID_dsaWithSHA1:
		case NID_dsaWithSHA1_2:
			md = EVP_sha1();
			break;
		case NID_dsa_with_SHA224:
			md = EVP_sha224();
			break;
		case NID_dsa_with_SHA256:
			md = EVP_sha256();
			break;
		default:
			md = EVP_sha256();
			break;
		}
		break;


	case EVP_PKEY_EC:
		switch (nid) {
		case NID_ecdsa_with_SHA1:
			md = EVP_sha1();
			break;
		case NID_ecdsa_with_SHA224:
			md = EVP_sha224();
			break;
		case NID_ecdsa_with_SHA256:
			md = EVP_sha256();
			break;
		case NID_ecdsa_with_SHA384:
			md = EVP_sha384();
			break;
		case NID_ecdsa_with_SHA512:
			md = EVP_sha512();
			break;
		default:
			md = EVP_sha256();
			break;
		}
		break;

	default:
		break;
	}

	return md;
}

/*
 * Create a fake X509v3 certificate, signed by the provided CA,
 * based on the original certificate retrieved from the real server.
 * The returned certificate is created using X509_new() and thus must
 * be freed by the caller using X509_free().
 * The optional argument extraname is added to subjectAltNames if provided.
 *
 * key: private key of new cert
 */
X509* ssl_x509_forge(X509* cacrt, EVP_PKEY* cakey, X509* origcrt, EVP_PKEY* key)
{
	X509* crt = NULL;
	int rv;

	//Subject: CN=albert
	X509_NAME* subject = X509_get_subject_name(origcrt);
	//Issuer: CN=albert-CA
	X509_NAME* issuer = X509_get_subject_name(cacrt);
	if (!subject || !issuer)
		return NULL;

	crt = X509_new();
	if (!crt)
		return NULL;

	ASN1_TIME* notbefore = X509_getm_notBefore(origcrt);
	ASN1_TIME* notafter = X509_getm_notAfter(origcrt);

	if (!X509_set_version(crt, 0x02) ||
		!X509_set_subject_name(crt, subject) ||
		!X509_set_issuer_name(crt, issuer) ||
		ssl_x509_serial_copyrand(crt, origcrt) == -1 ||
		!X509_set1_notBefore(crt, notbefore) ||
		!X509_set1_notAfter(crt, notafter) ||
		!X509_set_pubkey(crt, key))
		goto errout;

	/* add standard v3 extensions; cf. RFC 2459 */
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, cacrt, crt, NULL, NULL, 0);
	if (ssl_x509_v3ext_add(&ctx, crt, "subjectKeyIdentifier", "hash") == -1
		|| ssl_x509_v3ext_add(&ctx, crt, "authorityKeyIdentifier",
			"keyid,issuer:always") == -1)
		goto errout;

	rv = ssl_x509_v3ext_copy_by_nid(crt, origcrt, NID_basic_constraints);
	if (rv == 0)
		rv = ssl_x509_v3ext_add(&ctx, crt, "basicConstraints", "CA:FALSE");
	if (rv == -1)
		goto errout;

	/* key usage depends on the key type, do not copy from original */
	char* key_usage_str = ssl_key_usage_for_key(key);
	rv = ssl_x509_v3ext_add(&ctx, crt, "keyUsage", key_usage_str);
	if (rv == -1)
		goto errout;

	rv = ssl_x509_v3ext_copy_by_nid(crt, origcrt, NID_ext_key_usage);
	if (rv == 0)
		rv = ssl_x509_v3ext_add(&ctx, crt, "extendedKeyUsage", "serverAuth");
	if (rv == -1)
		goto errout;

	/* no extraname provided: copy original subjectAltName ext */
	if (ssl_x509_v3ext_copy_by_nid(crt, origcrt, NID_subject_alt_name) == -1)
		goto errout;

	int pkey_type = EVP_PKEY_type(EVP_PKEY_base_id(cakey));
	int sig_nid = X509_get_signature_nid(origcrt);
	const EVP_MD* md = get_cert_md(pkey_type, sig_nid);
	if (!X509_sign(crt, cakey, md))
		goto errout;
	return crt;

errout:
	X509_free(crt);
	return NULL;
}
