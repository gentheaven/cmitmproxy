#ifndef PROXY_H
#define PROXY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/dns.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>

#include "list.h"
#include "defaults.h"
#include "mid.h"

#include "mitm.h"

//#define DEBUG
//#define SUPPORT_CHUNK //Transfer-Encoding: chunked\r\n

#define ssize_t long long
#define strncasecmp _strnicmp
#define strcasecmp  _stricmp
#define strdup _strdup

/* Define to the full name of this package. */
#define PACKAGE_NAME "Cmitmproxy"

/* Name of package */
#define PACKAGE "cmitmproxy"

/* Version number of package */
#define VERSION "1.0"

#define LOG_CRIT	0
#define LOG_ERR		1
#define LOG_WARNING	2
#define LOG_NOTICE	3
#define LOG_CONN	4
#define LOG_INFO	5
#define	LOG_DEBUG	6

extern int glog_level;

#define MAX_URL_LEN 256
#define MAX_ERROR_MSG_LEN 256
#define MAX_HTTP_LEN (64 * 1024) //64KB

/*
INADDR_ANY: 0.0.0.0
default: 127.0.0.1:8080
*/
struct config_s {
	//configure paras
	char proxy_addr[32];
	int proxy_port;
	unsigned int idletimeout; //MAX_IDLE_TIME
	int max_clients; //MAX_CLIENTS
};

//mitm
struct mitm_ctx_st {
	struct list_head child_list_head;
	int childs_num; //http/https connection number

	CONFIG_S* config;
	struct event_base* base;
	struct event* signal_event;
	struct evconnlistener* listener;

	enum WORK_MODE mode;
	//CA
	X509* cacrt;
	EVP_PKEY* cakey;
	EVP_PKEY* leafkey;

	void* arg; //in/out for app
	cbfilter_by_host cb_host;
	cbfilter_by_http_header cb_cared;
	cb_http_response cb_response; //http response
};

/*
 * Connection Definition
 */
struct conn_s {
	//between client and proxy
	struct bufferevent* client_socket;
	evutil_socket_t fd;
	int retry_cnt; //try counter of reading from client
	int client_port; //proxy port with client, debug only
	// Store the incoming request's HTTP protocol.
	struct {
		unsigned int major;
		unsigned int minor;
	} protocol;
	int error_number;
	char error_string[MAX_ERROR_MSG_LEN];
	char detail_string[MAX_ERROR_MSG_LEN];

	//mitm
	SSL* client_ssl;
	void* http_ctx;//mid level, protohttp_ctx_t* http_ctx
	char http_buf[MAX_CHUNCK_LEN];//include http header and message content

	//between proxy and server, struct pxy_conn_desc srvdst
	struct evdns_base *dns_base;
	int port; //default is 443
	struct bufferevent* server_socket;
	SSL* server_ssl;
};

#define MAX_CLIENTS 10240
/*
 * Port constants for HTTP (80) and SSL (443)
 */
#define HTTP_PORT 80
#define HTTP_PORT_SSL 443

 /*
  * This structure holds the information pulled from a URL request.
  */
struct request_s {
	char* method;
	char* protocol;
	char* host;
	uint16_t port;
	char* path;
};

struct ssl_ctx {
	/* log strings related to SSL */
	char* ssl_names;
	char* origcrtfpr;
	char* usedcrtfpr;

	/* ssl */
	unsigned int generated_cert;     /* 1 if we generated a new cert */
	/* server name indicated by client in SNI TLS extension */
	char* sni;
	X509* origcrt;

	char* srvdst_ssl_version;
	char* srvdst_ssl_cipher;

	//remote server
	char server_ip[32];
};
typedef struct ssl_ctx ssl_ctx_t;

struct child {
	struct list_head child_list; //linux list

	struct conn_s conn; //connection info
	struct request_s req;

	int connected;//connected with remote server, set 1
	//For ssl specific fields, NULL for non-ssl conns
	struct ssl_ctx* sslctx;

	struct event* ev;

	//mitm
	struct mitm_ctx_st* mctx;
	enum FILTER_RESULT filter_res;
};


extern int win_env_init(void);
extern void win_env_exit(void);

extern void set_http_proxy(char* proxy_ip, unsigned short  port);
extern void reset_http_proxy(void);

//ip +  port to struct sockaddr_in
extern void init_sockaddr_in(struct sockaddr_in* dest, const char* ip, int port);

extern void print_char(char* name, uint8_t* buf, int len);
extern void print_hex(char* name, uint8_t* buf, int len);
extern void log_message(int level, const char* fmt, ...);

extern int get_sockpeer_port(evutil_socket_t sockfd);

extern int parse_connect_request(char* buf, int len, struct child* pchild);
/*
 * Free all the memory allocated in a request.
 */
extern void free_request_struct(struct request_s* request);

/*
 * Add the error information to the conn structure.
 */
extern void indicate_http_error(struct conn_s* connptr, int number, const char* message, ...);
extern int send_http_error_message(struct conn_s* connptr);

/*  mitm */
extern struct mitm_ctx_st* mitm_ctx_init(void);
extern void mitm_ctx_exit(struct mitm_ctx_st* ctx);

//return 0 if load OK
extern int mitm_loadCA(mitm_ctx* mctx, const char* cert_path, const char* cert_privkey_path);

extern void destroy_child_list(struct list_head* head, int count);

//free ctx->sslctx
extern void protossl_free(struct child* ctx);
extern void pxy_try_disconnect(struct child* ctx);

//parse SNI from clienthello packet
extern void protossl_fd_readcb(evutil_socket_t fd, short what, void* arg);

extern void protossl_bev_eventcb(struct bufferevent* bev, short events, void* arg);
extern void protohttp_bev_readcb(struct bufferevent* bev, void* arg);

extern SSL* protossl_dstssl_create(struct child* ctx);
extern struct bufferevent*
	protossl_bufferevent_setup(struct child* ctx, evutil_socket_t fd, SSL* ssl);

extern void protossl_bev_eventcb(struct bufferevent* bev, short events, void* arg);

//ssl
extern int ssl_ec_nid_by_name(const char* curvename);

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
extern EVP_PKEY* rsa_get_key_fromfile(const char* filename, int der, int public);

extern X509* get_cert(const char* path);

extern X509* ssl_x509_forge(X509* cacrt, EVP_PKEY* cakey, X509* origcrt, EVP_PKEY* key);

/*Returns:
*1  if found SNI
* 0  if not found
*/
extern int ssl_tls_clienthello_parse(const unsigned char* buf, int len, char** servername);

extern int opensock(struct child* pchild, const char* host, int port);

extern void mitm_freeCA(mitm_ctx* mctx);

extern void mitm_set_filter_mode(struct child* pchild);


#endif

