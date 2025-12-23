#include "proxy.h"


static void protohttp_bev_writecb(struct bufferevent* bev, void* arg);

//parse SNI from clienthello packet
void protossl_fd_readcb(evutil_socket_t fd, short what, void* arg)
{
	int len;
	struct child* pchild = (struct child*)arg;

	event_free(pchild->ev);
	pchild->ev = NULL;

	unsigned char data[2048];
	len = recv(fd, data, sizeof(data), MSG_PEEK);
	if (len <= 0) {
		printf("protossl_fd_readcb read error, ret = %d\n", len);
	} else {
		log_message(LOG_DEBUG, "protossl_fd_readcb read %d bytes\n", len);
		ssl_tls_clienthello_parse(data, len, &pchild->sslctx->sni);
	}

	//try to connect with remote server, pxy_conn_connect
	opensock(pchild, pchild->req.host, pchild->req.port);
	return;
}

void protossl_free(struct child* ctx)
{
	if (!ctx->sslctx)
		return;
	if (ctx->sslctx->ssl_names) {
		free(ctx->sslctx->ssl_names);
	}
	if (ctx->sslctx->origcrtfpr) {
		free(ctx->sslctx->origcrtfpr);
	}
	if (ctx->sslctx->usedcrtfpr) {
		free(ctx->sslctx->usedcrtfpr);
	}
	if (ctx->sslctx->origcrt) {
		X509_free(ctx->sslctx->origcrt);
	}
	if (ctx->sslctx->sni) {
		free(ctx->sslctx->sni);
	}
	if (ctx->sslctx->srvdst_ssl_version) {
		free(ctx->sslctx->srvdst_ssl_version);
	}
	if (ctx->sslctx->srvdst_ssl_cipher) {
		free(ctx->sslctx->srvdst_ssl_cipher);
	}
	free(ctx->sslctx);
	// It is necessary to NULL the sslctx to prevent passthrough mode trying to access it (signal 11 crash)
	ctx->sslctx = NULL;
}

/*
 * Set SSL_CTX options that are the same for incoming and outgoing SSL_CTX.
 */
static void
protossl_sslctx_setoptions(SSL_CTX* sslctx, struct child* ctx)
{
	SSL_CTX_set_options(sslctx, SSL_OP_ALL);
	SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
	SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
	SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);

	SSL_CTX_set_cipher_list(sslctx, DFLT_CIPHERS); //ALL:-aNULL
	//TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
	SSL_CTX_set_ciphersuites(sslctx, DFLT_CIPHERSUITES);
	SSL_CTX_set_security_level(sslctx, 1);
}

static void keylog_callback(const SSL* ssl, const char* line)
{
	//wireshark could crack in time only after close log file
	FILE* fp = fopen("r:\\log.txt", "a");
	if (fp) {
		fprintf(fp, "%s\n", line);
		fclose(fp);
	}
}

/*
 * Create new SSL context for outgoing connections to the original destination.
 * If hostname sni is provided, use it for Server Name Indication.
 */
SSL* protossl_dstssl_create(struct child* ctx)
{
	SSL_CTX* sslctx;
	SSL* ssl = NULL;

	const SSL_METHOD* method = TLS_method();
	sslctx = SSL_CTX_new(method);

#ifdef DEBUG
	SSL_CTX_set_keylog_callback(sslctx, keylog_callback);
#endif

	protossl_sslctx_setoptions(sslctx, ctx);
	SSL_CTX_set_min_proto_version(sslctx, 0x0301);
	SSL_CTX_set_max_proto_version(sslctx, 0x0304);
	SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx);

	if (ctx->sslctx->sni) {
		SSL_set_tlsext_host_name(ssl, ctx->sslctx->sni);
	}
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
	return ssl;
}

/*
 * Set up a bufferevent structure for either a dst or src connection,
 * optionally with or without SSL.  Sets all callbacks, enables read
 * and write events, but does not call bufferevent_socket_connect().
 *
 * For dst connections, pass -1 as fd.  Pass a pointer to an initialized
 * SSL struct as ssl if the connection should use SSL.
 *
 * Returns pointer to initialized bufferevent structure, as returned
 * by bufferevent_socket_new() or bufferevent_openssl_socket_new().
 */
struct bufferevent* 
protossl_bufferevent_setup(struct child* ctx, evutil_socket_t fd, SSL* ssl)
{
	struct event_base* base = ctx->mctx->base;

	struct bufferevent* bev = bufferevent_openssl_socket_new(base, fd, ssl,
		((fd == -1) ? BUFFEREVENT_SSL_CONNECTING : BUFFEREVENT_SSL_ACCEPTING), BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		log_message(LOG_CRIT, "Error creating bufferevent socket\n");
		return NULL;
	}

	log_message(LOG_INFO, "bufferevent_openssl_set_allow_dirty_shutdown, fd=%d\n", fd);

	/* Prevent unclean (dirty) shutdowns to cause error
	 * events on the SSL socket bufferevent. */
	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

	// @attention Do not set callbacks here, we do not set r cb for tcp/ssl srvdst
	//bufferevent_setcb(bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	// @attention Do not enable r/w events here, we do not set r cb for tcp/ssl srvdst
	// Also, to avoid r/w cb before connected, we should enable r/w events after the conn is connected
	//bufferevent_enable(bev, EV_READ|EV_WRITE);
	return bev;
}

void prototcp_bev_eventcb_src(struct bufferevent* bev,
	short events, struct child* ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		log_message(LOG_DEBUG, "connected with client\n");
		return;
	}
}

static X509* protossl_srccert_create(struct child* ctx)
{
	X509* cert = NULL;
	mitm_ctx* mctx = ctx->mctx;
	cert = ssl_x509_forge(mctx->cacrt, mctx->cakey,
		ctx->sslctx->origcrt, mctx->leafkey);
	return cert;
}

/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and key.
 */
static SSL_CTX*
protossl_srcsslctx_create(struct child* ctx, X509* crt, EVP_PKEY* key)
{
	const SSL_METHOD* method = TLS_method();
	SSL_CTX* sslctx = SSL_CTX_new(method);

#ifdef DEBUG
	SSL_CTX_set_keylog_callback(sslctx, keylog_callback);
#endif

	protossl_sslctx_setoptions(sslctx, ctx);
	SSL_CTX_set_min_proto_version(sslctx, 0x0301);
	SSL_CTX_set_max_proto_version(sslctx, 0x0304);

	//SSL_CTX_set_tlsext_servername_callback(sslctx, protossl_ossl_servername_cb);
	//SSL_CTX_set_tlsext_servername_arg(sslctx, ctx);

	SSL_CTX_set_dh_auto(sslctx, 1);
	int nid = ssl_ec_nid_by_name(0); //415
	int rv = SSL_CTX_set1_groups(sslctx, &nid, 1);
	if (!rv) {
		log_message(LOG_ERR, "failed setting ecdh curve\n");
		SSL_CTX_free(sslctx);
		return NULL;
	}

	if (SSL_CTX_use_certificate(sslctx, crt) != 1) {
		log_message(LOG_ERR, "loading src server certificate failed\n");
		SSL_CTX_free(sslctx);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey(sslctx, key) != 1) {
		log_message(LOG_ERR, "loading src server key failed\n");
		SSL_CTX_free(sslctx);
		return NULL;
	}

	return sslctx;
}

/*
 * Create new SSL context for the incoming connection, based on the original
 * destination SSL certificate.
 * Returns NULL if no suitable certificate could be found or the site should
 * be passed through.
 */
static SSL*
protossl_srcssl_create(struct child* ctx, SSL* origssl)
{
	ctx->sslctx->origcrt = SSL_get_peer_certificate(origssl);
	X509* cert = protossl_srccert_create(ctx);
	if (!cert)
		return NULL;

	SSL_CTX* sslctx = protossl_srcsslctx_create(ctx, cert, ctx->mctx->leafkey);
	X509_free(cert);
	if (!sslctx)
		return NULL;
	SSL* ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx);

	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
	return ssl;
}

int protossl_enable_src(struct child* ctx)
{
	struct conn_s* connptr = &ctx->conn;
	connptr->client_socket = protossl_bufferevent_setup(ctx, connptr->fd, connptr->client_ssl);
	if (!connptr->client_socket) {
		log_message(LOG_ERR, "Error creating src bufferevent\n");
		SSL_free(connptr->client_ssl);
		connptr->client_ssl = NULL;
		return -1;
	}

	struct bufferevent* client = connptr->client_socket;
	bufferevent_setcb(client, protohttp_bev_readcb, protohttp_bev_writecb, protossl_bev_eventcb, ctx);

	// Now open the gates
	bufferevent_enable(client, EV_READ | EV_WRITE);
	return 0;
}

//mid level: handle http packet
static int mid_handle_http(int c2s,
	struct evbuffer* inbuf, struct evbuffer* outbuf,
	struct child* ctx)
{
	struct conn_s* pconn = &ctx->conn;
	void* http_ctx = pconn->http_ctx;

	size_t http_len = evbuffer_get_length(inbuf);
	char* http;
	if (http_len > MAX_CHUNCK_LEN)
		http = malloc(http_len);
	else
		http = pconn->http_buf;
	evbuffer_copyout(inbuf, http, http_len); //copy to http[http_len]

	enum packet_handle_result ret = PACKET_FORWARD;
	int change = 0;
	char* out = NULL;
	size_t out_len = 0;
	ret = protohttp_handle(c2s, http, http_len, http_ctx, &out, &out_len);
	if (PACKET_FORWARD == ret) {
		change = 0;
		goto clean;
	}

	change = 1;
	evbuffer_drain(inbuf, http_len); //remove original content
	if (PACKET_DISCARD == ret)
		goto clean;

	//PACKET_CHANGE, add new content
	if(out && out_len)
		evbuffer_add(outbuf, out, out_len);

clean:
	if (http_len > MAX_CHUNCK_LEN)
		free(http);

	return change;
}

void protohttp_bev_readcb(struct bufferevent* bev, void* arg)
{
	struct child* ctx = (struct child*)arg;
	struct bufferevent *client, *server;
	struct conn_s* pconn = &ctx->conn;
	client = pconn->client_socket;
	server = pconn->server_socket;

	struct bufferevent* peer;
	int c2s = 0;
	if (bev == client) {
		peer = server;
		c2s = 1;
	}else {
		peer = client;
		c2s = 0;
	}

	struct evbuffer* inbuf = bufferevent_get_input(bev);
	struct evbuffer* outbuf = bufferevent_get_output(peer);

	int forward = 0;
	if (FILTER_RESULT_PASS == ctx->filter_res) {
		forward = 1;
	} else if (!ctx->mctx->cb_response) {
		//not cared this http content
		forward = 1;
	} else {
		int change = mid_handle_http(c2s, inbuf, outbuf, ctx);
		if (change) {
			forward = 0;
		} else {
			forward = 1;
		}	
	}
	
	//forward mode for this connetion
	if (forward) {
		evbuffer_add_buffer(outbuf, inbuf);
	}
}

static void protohttp_bev_writecb(struct bufferevent* bev, void* arg)
{
}

//connected with remote server, now set proxy with client, proxy as server
static void protossl_bev_eventcb_connected_srvdst(
	struct bufferevent* bev, struct child* ctx)
{
	struct conn_s* connptr = &ctx->conn;
	connptr->client_ssl = protossl_srcssl_create(ctx, connptr->server_ssl);
	if (!connptr->client_ssl)
		return;

	struct bufferevent* server = connptr->server_socket;
	bufferevent_setcb(server, protohttp_bev_readcb, protohttp_bev_writecb, protossl_bev_eventcb, ctx);
	bufferevent_enable(server, EV_READ | EV_WRITE);
	protossl_enable_src(ctx);
}

void protossl_bev_eventcb_srvdst(struct bufferevent* bev,
	short events, struct child* ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protossl_bev_eventcb_connected_srvdst(bev, ctx);
		log_message(LOG_DEBUG, "connected with server\n");
		return;
	}
}

void protossl_bev_eventcb(struct bufferevent* bev, short events, void* arg)
{
	struct child* ctx = (struct child*)arg;
	struct bufferevent *client, *server;

	client = ctx->conn.client_socket;
	server = ctx->conn.server_socket;
	if (events & BEV_EVENT_CONNECTED) {
		if (bev == client) {
			prototcp_bev_eventcb_src(bev, events, ctx);
		} else if (bev == server) {
			protossl_bev_eventcb_srvdst(bev, events, ctx);
		}
		return;
	}

	//error
	char* host = ctx->req.host;
	if (bev == client) {
		log_message(LOG_DEBUG, "%s: client closed, events=0x%x\n", host, events);
	} else {
		log_message(LOG_DEBUG, "%s: server closed, events=0x%x\n", host, events);
	}
	pxy_try_disconnect(ctx);
}

