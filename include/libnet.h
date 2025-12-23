/*
 *  $Id: libnet.h,v 1.7 2004/01/03 20:31:00 mike Exp $
 *
 *  libnet.h - Network routine library header file for Win32 VC++
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __LIBNET_H
#define __LIBNET_H

#define LIBNET_LIL_ENDIAN 1

#define PACKET_GET_2(buf) ntohs(*(uint16_t*)(buf))

#pragma pack(push, 1)

 /*
  *  IPv4 header
  *  Internet Protocol, version 4
  *  Static header size: 20 bytes
  */
struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    uint8_t ip_hl : 4,      /* header length */
        ip_v : 4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    uint8_t ip_v : 4,       /* version */
        ip_hl : 4;        /* header length */
#endif
    uint8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    uint8_t  th_x2 : 4,         /* (unused) */
        th_off : 4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    uint8_t  th_off : 4,        /* data offset */
        th_x2 : 4;         /* (unused) */
#endif
    uint8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};


//https://rfc2cn.com/rfc5246.html

//6.2. Record Layer
struct ProtocolVersion {
    uint8_t major;
    uint8_t minor;
};

struct TLSRecord {
    uint8_t type;
    struct ProtocolVersion version;
    uint16_t length;
    char* fragment;
};

#define TLS_RECORD_LEN 5

struct TLSHandshake {
    uint8_t msg_type;    /* handshake type */
    uint8_t length[3];   /* bytes in message */
    char* body;
};

#define TLS_HS_LEN 4 //handshake len

/*
* 7.4.1.2. Client Hello
* 
* opaque SessionID<0..32>;

struct {
    ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suites<2..2 ^ 16 - 2>;
    CompressionMethod compression_methods<1..2 ^ 8 - 1>;
    select(extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2 ^ 16 - 1>;
    };
} ClientHello;
*/
struct SSlHello {
    struct ProtocolVersion client_version;
    uint8_t random[32];
    uint8_t session_id_len;
    uint8_t session_id[32];
};

/*
struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
} Extension;
*/
struct hello_extension {
    uint16_t type;
    uint16_t length;
    char* extension_data;
};

//https://rfc2cn.com/rfc6066.html
/*
struct {
        NameType name_type;
        select (name_type) {
            case host_name: HostName;
        } name;
    } ServerName;

    opaque HostName<1..2^16-1>;

    struct {
          ServerName server_name_list<1..2^16-1>
      } ServerNameList;
*/

struct ext_ServerName {
    uint8_t name_type;
    uint16_t length;
    char* hostName;
};

struct ext_ServerNameList {
    uint16_t list_length;
    struct ext_ServerName* sni;
};

/*
struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce<0..255>;
          opaque ticket<1..2^16-1>;
          Extension extensions<0..2^16-2>;
      } NewSessionTicket;
*/
struct new_session_ticket {
    uint32_t lifetime;
    uint32_t age_add;
    uint8_t nonce_len;
    uint8_t* nonce; //uint8_t nonce[nonce_len]
};
#define NEW_SESSION_TICKET_NONCE_OFFSET 9

/* 4.4.2. Certificate
enum {
    X509(0),
    RawPublicKey(2),
    (255)
} CertificateType;

struct {
    select (certificate_type) {
        case RawPublicKey:
        // From RFC 7250 ASN.1_subjectPublicKeyInfo
        opaque ASN1_subjectPublicKeyInfo<1..2 ^ 24 - 1>;

        case X509:
            opaque cert_data<1..2 ^ 24 - 1>;
    };
    Extension extensions<0..2 ^ 16 - 1>;
} CertificateEntry;

struct {
    opaque certificate_request_context<0..2 ^ 8 - 1>;
    CertificateEntry certificate_list<0..2 ^ 24 - 1>;
} Certificate;

certificate_list:  A sequence (chain) of CertificateEntry structures,
      each containing a single certificate and set of extensions.
*/

struct cert_extension {
    uint16_t len;
    char* ext;//ext[len]
};

struct CertificateEntry {
    uint8_t cert_data_len[3];   /* bytes in message */
    char* cert_data; //body[cert_data_len]
    //Extension extensions<0..2 ^ 16 - 1>;
};
#define CERT_EXT_OFFSET(len) (3 + len)


struct Certificate {
    uint8_t request_context_len;
    char* request_context; //request_context[request_context_len]
    //certificate_list
};
#define CERTIFICATE_OFFSET(len) (1 + len)

struct CertificateEntry_list {
    uint8_t cert_list_len[3];   // certificate_list total bytes
    struct CertificateEntry* entrys;
};


/* RFC8446 4.4.3. Certificate Verify
enum {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256(0x0401),
    rsa_pkcs1_sha384(0x0501),
    rsa_pkcs1_sha512(0x0601),
    ...

     // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256(0x0804),
    rsa_pss_rsae_sha384(0x0805),
    rsa_pss_rsae_sha512(0x0806),
}SignatureScheme;

struct {
    SignatureScheme algorithm;
    opaque signature<0..2 ^ 16 - 1>;
} CertificateVerify;

*/
struct CertificateVerify {
    uint16_t algorithm;
    uint16_t signature_len;
    char* signature;
};


#pragma pack(pop)

//copied from openssl-3.5.4-src\openssl-3.5.4\ssl\t1_trce.c
typedef struct {
    int num;
    const char* name;
} ssl_trace_tbl;

extern const ssl_trace_tbl ssl_exts_tbl[];
extern const ssl_trace_tbl ssl_groups_tbl[];
extern const ssl_trace_tbl ssl_handshake_tbl[];
extern const ssl_trace_tbl ssl_ciphers_tbl[];
extern const ssl_trace_tbl ssl_content_tbl[];

extern size_t ssl_exts_tbl_num;
extern size_t ssl_groups_tbl_num;
extern size_t ssl_handshake_tbl_num;
extern size_t ssl_ciphers_tbl_num;
extern size_t ssl_content_tbl_num;

extern const char* do_ssl_trace_str(int val, const ssl_trace_tbl* tbl, size_t ntbl);
extern const char* got_SignatureScheme_name(uint16_t id);

/* Sigalgs values */
#define TLSEXT_SIGALG_ecdsa_secp256r1_sha256                    0x0403
#define TLSEXT_SIGALG_ecdsa_secp384r1_sha384                    0x0503
#define TLSEXT_SIGALG_ecdsa_secp521r1_sha512                    0x0603
#define TLSEXT_SIGALG_ecdsa_sha224                              0x0303
#define TLSEXT_SIGALG_ecdsa_sha1                                0x0203
#define TLSEXT_SIGALG_rsa_pss_rsae_sha256                       0x0804
#define TLSEXT_SIGALG_rsa_pss_rsae_sha384                       0x0805
#define TLSEXT_SIGALG_rsa_pss_rsae_sha512                       0x0806
#define TLSEXT_SIGALG_rsa_pss_pss_sha256                        0x0809
#define TLSEXT_SIGALG_rsa_pss_pss_sha384                        0x080a
#define TLSEXT_SIGALG_rsa_pss_pss_sha512                        0x080b
#define TLSEXT_SIGALG_rsa_pkcs1_sha256                          0x0401
#define TLSEXT_SIGALG_rsa_pkcs1_sha384                          0x0501
#define TLSEXT_SIGALG_rsa_pkcs1_sha512                          0x0601
#define TLSEXT_SIGALG_rsa_pkcs1_sha224                          0x0301
#define TLSEXT_SIGALG_rsa_pkcs1_sha1                            0x0201
#define TLSEXT_SIGALG_dsa_sha256                                0x0402
#define TLSEXT_SIGALG_dsa_sha384                                0x0502
#define TLSEXT_SIGALG_dsa_sha512                                0x0602
#define TLSEXT_SIGALG_dsa_sha224                                0x0302
#define TLSEXT_SIGALG_dsa_sha1                                  0x0202
#define TLSEXT_SIGALG_gostr34102012_256_intrinsic               0x0840
#define TLSEXT_SIGALG_gostr34102012_512_intrinsic               0x0841
#define TLSEXT_SIGALG_gostr34102012_256_gostr34112012_256       0xeeee
#define TLSEXT_SIGALG_gostr34102012_512_gostr34112012_512       0xefef
#define TLSEXT_SIGALG_gostr34102001_gostr3411                   0xeded

#define TLSEXT_SIGALG_ed25519                                   0x0807
#define TLSEXT_SIGALG_ed448                                     0x0808
#define TLSEXT_SIGALG_ecdsa_brainpoolP256r1_sha256              0x081a
#define TLSEXT_SIGALG_ecdsa_brainpoolP384r1_sha384              0x081b
#define TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512              0x081c
#define TLSEXT_SIGALG_mldsa44                                   0x0904
#define TLSEXT_SIGALG_mldsa65                                   0x0905
#define TLSEXT_SIGALG_mldsa87                                   0x0906

/* Sigalgs names */
#define TLSEXT_SIGALG_ecdsa_secp256r1_sha256_name                    "ecdsa_secp256r1_sha256"
#define TLSEXT_SIGALG_ecdsa_secp384r1_sha384_name                    "ecdsa_secp384r1_sha384"
#define TLSEXT_SIGALG_ecdsa_secp521r1_sha512_name                    "ecdsa_secp521r1_sha512"
#define TLSEXT_SIGALG_ecdsa_sha224_name                              "ecdsa_sha224"
#define TLSEXT_SIGALG_ecdsa_sha1_name                                "ecdsa_sha1"
#define TLSEXT_SIGALG_rsa_pss_rsae_sha256_name                       "rsa_pss_rsae_sha256"
#define TLSEXT_SIGALG_rsa_pss_rsae_sha384_name                       "rsa_pss_rsae_sha384"
#define TLSEXT_SIGALG_rsa_pss_rsae_sha512_name                       "rsa_pss_rsae_sha512"
#define TLSEXT_SIGALG_rsa_pss_pss_sha256_name                        "rsa_pss_pss_sha256"
#define TLSEXT_SIGALG_rsa_pss_pss_sha384_name                        "rsa_pss_pss_sha384"
#define TLSEXT_SIGALG_rsa_pss_pss_sha512_name                        "rsa_pss_pss_sha512"
#define TLSEXT_SIGALG_rsa_pkcs1_sha256_name                          "rsa_pkcs1_sha256"
#define TLSEXT_SIGALG_rsa_pkcs1_sha384_name                          "rsa_pkcs1_sha384"
#define TLSEXT_SIGALG_rsa_pkcs1_sha512_name                          "rsa_pkcs1_sha512"
#define TLSEXT_SIGALG_rsa_pkcs1_sha224_name                          "rsa_pkcs1_sha224"
#define TLSEXT_SIGALG_rsa_pkcs1_sha1_name                            "rsa_pkcs1_sha1"
#define TLSEXT_SIGALG_dsa_sha256_name                                "dsa_sha256"
#define TLSEXT_SIGALG_dsa_sha384_name                                "dsa_sha384"
#define TLSEXT_SIGALG_dsa_sha512_name                                "dsa_sha512"
#define TLSEXT_SIGALG_dsa_sha224_name                                "dsa_sha224"
#define TLSEXT_SIGALG_dsa_sha1_name                                  "dsa_sha1"
#define TLSEXT_SIGALG_gostr34102012_256_intrinsic_name               "gostr34102012_256"
#define TLSEXT_SIGALG_gostr34102012_512_intrinsic_name               "gostr34102012_512"
#define TLSEXT_SIGALG_gostr34102012_256_intrinsic_alias              "gost2012_256"
#define TLSEXT_SIGALG_gostr34102012_512_intrinsic_alias              "gost2012_512"
#define TLSEXT_SIGALG_gostr34102012_256_gostr34112012_256_name       "gost2012_256"
#define TLSEXT_SIGALG_gostr34102012_512_gostr34112012_512_name       "gost2012_512"
#define TLSEXT_SIGALG_gostr34102001_gostr3411_name                   "gost2001_gost94"

#define TLSEXT_SIGALG_ed25519_name                                   "ed25519"
#define TLSEXT_SIGALG_ed448_name                                     "ed448"
#define TLSEXT_SIGALG_ecdsa_brainpoolP256r1_sha256_name              "ecdsa_brainpoolP256r1tls13_sha256"
#define TLSEXT_SIGALG_ecdsa_brainpoolP384r1_sha384_name              "ecdsa_brainpoolP384r1tls13_sha384"
#define TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512_name              "ecdsa_brainpoolP512r1tls13_sha512"
#define TLSEXT_SIGALG_ecdsa_brainpoolP256r1_sha256_alias             "ecdsa_brainpoolP256r1_sha256"
#define TLSEXT_SIGALG_ecdsa_brainpoolP384r1_sha384_alias             "ecdsa_brainpoolP384r1_sha384"
#define TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512_alias             "ecdsa_brainpoolP512r1_sha512"
#define TLSEXT_SIGALG_mldsa44_name                                   "mldsa44"
#define TLSEXT_SIGALG_mldsa65_name                                   "mldsa65"
#define TLSEXT_SIGALG_mldsa87_name                                   "mldsa87"

/* Known PSK key exchange modes */
#define TLSEXT_KEX_MODE_KE                                      0x00
#define TLSEXT_KEX_MODE_KE_DHE                                  0x01

/*
 * Internal representations of key exchange modes
 */
#define TLSEXT_KEX_MODE_FLAG_NONE                               0
#define TLSEXT_KEX_MODE_FLAG_KE                                 1
#define TLSEXT_KEX_MODE_FLAG_KE_DHE                             2


#endif
