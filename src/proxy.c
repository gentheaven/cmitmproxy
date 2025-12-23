#include <signal.h>

#include "proxy.h"

static struct config_s gconfig;
int glog_level = LOG_ERR; //LOG_INFO; //LOG_ERR;LOG_DEBUG;

int start_proxy_server(struct mitm_ctx_st* mctx, evconnlistener_cb cb);
static void on_new_connection(struct evconnlistener* listener, 
	evutil_socket_t fd, struct sockaddr* sa, int socklen, void* user_data);
static void server_eventcb(struct bufferevent* bev, short what, void* ctx);

int load_config(char* ip, unsigned short port, struct config_s* pconfig)
{
	if (ip)
		strcpy(pconfig->proxy_addr, ip);
	else
		strcpy(pconfig->proxy_addr, DEFAULT_PROXY_ADDR);

	if (port)
		pconfig->proxy_port = port;
	else
		pconfig->proxy_port = DEFAULT_PROXY_PORT;
	return 0;
}

static void signal_cb(evutil_socket_t sig, short events, void* user_data)
{
	struct event_base* base = user_data;
	struct timeval delay = { 2, 0 };

	printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");
	event_base_loopexit(base, &delay);
}

struct event_base* win_iocp_base(void)
{
	//if not set, proxy can't get any TCP connect
	evthread_use_windows_threads();

	struct event_config* cfg = event_config_new();
	event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);
	struct event_base* base;
	base = event_base_new_with_config(cfg);
	event_config_free(cfg);
	return base;
}

/*
input:
	bind ip:port

do:
	1. save ip:port to config
	2. set http proxy
	3. init windows socket env
	4. init mitm content: create event base
	5. it exits cleanly in response to a SIGINT (ctrl-c).

return:
	mitm contex
*/
mitm_ctx* mitm_init(char* ip, unsigned short port)
{
	memset(&gconfig, 0, sizeof(struct config_s));
	load_config(ip, port, &gconfig);
#ifdef DEBUG
#else
	set_http_proxy(gconfig.proxy_addr, gconfig.proxy_port);
#endif

	struct mitm_ctx_st* mctx = mitm_ctx_init();
	int ret = mitm_loadCA(mctx, "res\\RootCA.crt", "res\\RootCA.key");
	if (ret) {
		mitm_ctx_exit(mctx);
		return NULL;
	}
	mctx->mode = DEFAULT_WORK_MODE;
	mctx->config = &gconfig;

	win_env_init();
	mctx->base = win_iocp_base();
	mctx->signal_event = evsignal_new(mctx->base, 
		SIGINT, signal_cb, (void*)mctx->base);

	return (mitm_ctx*)mctx;
}

int mitm_run(struct mitm_ctx_st* mctx, void* arg)
{
	mctx->arg = arg;

	if (mctx->mode == WORK_MODE_FORWARD) {
		printf("proxy is working on forward mode\n");
	} else {
		if(mctx->cb_host)
			printf("proxy mode: decrypt specified https traffic\n");
		else
			printf("proxy mode: decrypt all https traffic\n");

		if(mctx->cb_cared)
			printf("proxy mode: filter by cared\n\n");
		else
			printf("proxy mode: cared about all\n\n");
	}
	//Start listening on the selected port
	if (start_proxy_server(mctx, on_new_connection)) {
		//start server failed
		return 1;
	}

	printf("Starting main loop. Accepting connections.\n\n");
	event_base_dispatch(mctx->base);
	return 0;
}

void mitm_exit(struct mitm_ctx_st* mctx)
{
	if (!mctx)
		return;
	//clean action
	if(mctx->listener)
		evconnlistener_free(mctx->listener);
	if(mctx->base)
		event_base_loopexit(mctx->base, NULL);
	mitm_ctx_exit(mctx);
	win_env_exit();

#ifdef DEBUG
#else
	reset_http_proxy();
#endif
}

void child_struct_init(struct child* pchild, struct mitm_ctx_st* mctx)
{
	memset(pchild, 0, sizeof(struct child));
	pchild->sslctx = malloc(sizeof(struct ssl_ctx));
	memset(pchild->sslctx, 0, sizeof(struct ssl_ctx));

	pchild->mctx = mctx;
	pchild->conn.http_ctx = protohttp_init_ctx(
		mctx->arg, mctx->cb_cared, mctx->cb_response);
}

void free_conn(struct child* pchild)
{
	free_request_struct(&pchild->req);
	protossl_free(pchild);
	protohttp_free_ctx(pchild->conn.http_ctx);

	if (pchild->conn.client_socket)
		bufferevent_free(pchild->conn.client_socket);
	if (pchild->conn.server_socket)
		bufferevent_free(pchild->conn.server_socket);
	free(pchild);
}

void clean_connection(struct child* pchild)
{
	pchild->mctx->childs_num--;
	list_del(&pchild->child_list);
	free_conn(pchild);
}

void destroy_child_list(struct list_head* head, int count)
{
	struct child* cur;
	struct child* n;
	int cnt = 0;
	list_for_each_entry_safe(cur, n, head, child_list, struct child) {
		cnt++;
		list_del(&cur->child_list);
		free_conn(cur);
	}
}

void protossl_bufferevent_free_and_close_fd(struct bufferevent* bev)
{
	if (!bev)
		return;
	SSL* ssl = bufferevent_openssl_get_ssl(bev);
	evutil_socket_t fd = bufferevent_getfd(bev);

	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	if (ssl) {
		SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(ssl);
	}

	bufferevent_disable(bev, EV_READ | EV_WRITE);
	bufferevent_free(bev);

	if(ssl)
		SSL_free(ssl);
	if (fd >= 0)
		evutil_closesocket(fd);
}

/*
* protossl_bufferevent_free_and_close_fd
 * Free bufferevent and close underlying socket properly.
 * For OpenSSL bufferevents, this will shutdown the SSL connection.
 */
void pxy_try_disconnect(struct child* ctx)
{
	protossl_bufferevent_free_and_close_fd(ctx->conn.client_socket);
	protossl_bufferevent_free_and_close_fd(ctx->conn.server_socket);
	ctx->conn.client_socket = NULL;
	ctx->conn.server_socket = NULL;
	clean_connection(ctx);
}

/*
 * Complete the connection.  This gets called after finding out where to
 * connect to.
 */
void pxy_conn_connect(struct child* pchild)
{
	struct conn_s* connptr = &pchild->conn;
	const char* hostname = (const char*)pchild->req.host;
	struct event_base* base = pchild->mctx->base;

	/* create server-side socket and eventbuffer */
	connptr->server_ssl = protossl_dstssl_create(pchild);
	if (!connptr->server_ssl) {
		clean_connection(pchild);
		return;
	}

	connptr->server_socket = protossl_bufferevent_setup(pchild, -1, connptr->server_ssl);
	if (!connptr->server_socket) {
		log_message(LOG_ERR, "Error creating srvdst \n");
		SSL_free(connptr->server_ssl);
		connptr->server_ssl = NULL;
		clean_connection(pchild);
		return;
	}

	struct bufferevent* server = connptr->server_socket;
	// Disable and NULL r/w cbs, we do nothing for srvdst in r/w cbs
	bufferevent_setcb(server, NULL, NULL, protossl_bev_eventcb, pchild);

	//connect with remote server, trigger the SSL handshake
	struct sockaddr_in sin;
	init_sockaddr_in(&sin, pchild->sslctx->server_ip, connptr->port);
	int ret = bufferevent_socket_connect(server,
		(struct sockaddr*)&sin, sizeof(struct sockaddr_in));
	if (ret < 0) {
		clean_connection(pchild);
		log_message(LOG_ERR, "%s connect failed \n", hostname);
	}
}

void on_resolved(int errcode, struct evutil_addrinfo* addr, void* ptr)
{
	struct child* pchild = (struct child*)ptr;
	struct conn_s* connptr = &pchild->conn;
	const char* hostname = (const char*)pchild->req.host;

	if (errcode) {
		printf("DNS query for %s failed: %s\n",
			hostname, evutil_gai_strerror(errcode));
		goto clean;
	}

	//use first ip
	struct evutil_addrinfo* ai = addr;
	struct sockaddr_in* sin = (struct sockaddr_in*)ai->ai_addr;
	char ip_str[128];
	evutil_inet_ntop(AF_INET, &sin->sin_addr, ip_str, 128);
	log_message(LOG_INFO, "%s ip: %s \n", hostname, ip_str);
	strcpy(pchild->sslctx->server_ip, ip_str);

	//clean
	evutil_freeaddrinfo(addr);
	evdns_base_free(pchild->conn.dns_base, 0);
	pchild->conn.dns_base = NULL;

	//here, DNS query finished, try to connect with remote server
	pxy_conn_connect(pchild);
	return;

clean:
	if(addr)
		evutil_freeaddrinfo(addr);
	evdns_base_free(pchild->conn.dns_base, 0);
	pchild->conn.dns_base = NULL;
	clean_connection(pchild);
}

/*
 * Open a connection to a remote host.  It's been re-written to use
 * the getaddrinfo() library function, which allows for a protocol
 * independent implementation (mostly for IPv4 and IPv6 addresses.)
 * https://libevent.org/libevent-book/Ref9_dns.html
 */
int opensock(struct child* pchild, const char* host, int port)
{
	struct conn_s* connptr = &pchild->conn;
	struct event_base* base = pchild->mctx->base;

	connptr->port = port;
	connptr->dns_base = evdns_base_new(base, 1);

	struct evutil_addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = EVUTIL_AI_CANONNAME;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct evdns_getaddrinfo_request* req = evdns_getaddrinfo(
		connptr->dns_base, host, NULL,
		&hints, on_resolved, (void*)pchild);
	if (!req)
		log_message(LOG_INFO, "request DNS query failed: %s\n", host);

	return 0;
}

//passthrough mode
int opensock_pass(struct child* pchild, const char* host, int port)
{
	struct conn_s* connptr = &pchild->conn;
	struct event_base* base = pchild->mctx->base;

	connptr->port = port;
	connptr->dns_base = evdns_base_new(base, 1);

	connptr->server_socket = bufferevent_socket_new(base, -1,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_setcb(connptr->server_socket, NULL, NULL, server_eventcb, (void*)pchild);

	int ret = bufferevent_socket_connect_hostname(
		connptr->server_socket, connptr->dns_base, AF_INET,
		host, port);
	if (ret) {
		log_message(LOG_INFO, "request DNS query failed: %s\n", host);
		return ret;
	}
	return 0;
}

//set client bufferevent and try to connect with remote server
int set_passthrough_mode(struct child* pchild)
{
	struct mitm_ctx_st* mctx = pchild->mctx;
	struct bufferevent* client;
	client = bufferevent_socket_new(mctx->base, pchild->conn.fd,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!client) {
		return -1;
	}
	pchild->conn.client_socket = client;
	bufferevent_setcb(client, NULL, NULL, NULL, (void*)pchild);

	//try to connect with remote server
	opensock_pass(pchild, pchild->req.host, pchild->req.port);
	return 0;
}

/*
0x0000000657FBEF30  43 4f 4e 4e 45 43 54 20 6c 6f 63 61 6c 68 6f 73  CONNECT localhos
0x0000000657FBEF40  74 3a 34 34 33 20 48 54 54 50 2f 31 2e 30 0d 0a  t:443 HTTP/1.0..
0x0000000657FBEF50  50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e  Proxy-Connection
0x0000000657FBEF60  3a 20 4b 65 65 70 2d 41 6c 69 76 65 0d 0a 0d 0a  : Keep-Alive....

CONNECT localhost:443 HTTP/1.0\r\n
*/
static void
proxy_read_connect_req(evutil_socket_t fd, short what, void* arg)
{
	struct child* pchild = (struct child*)arg;
	struct conn_s* connptr = &pchild->conn;

	event_free(pchild->ev);
	pchild->ev = NULL;
	
	unsigned char buf[1024];
	int	nread = recv(fd, buf, sizeof(buf), 0);
	if (nread <= 0) {
		if (connptr->retry_cnt >= 3) {
			//printf("proxy_read_connect_req read error, ret = %d\n", nread);
			goto done;
		}
		//retry 3 times
		connptr->retry_cnt++;
		pchild->ev = event_new(pchild->mctx->base, fd,
			EV_READ, proxy_read_connect_req, pchild);
		event_add(pchild->ev, NULL);
		return;
	}

	//read success, set counter to zero
	if(connptr->retry_cnt)
		log_message(LOG_DEBUG, "proxy_read_connect_req try counter = %d\n", connptr->retry_cnt);
	connptr->retry_cnt = 0;
	log_message(LOG_DEBUG, "proxy_read_connect_req, read connect request %d bytes\n", nread);

	if (parse_connect_request(buf, (int)nread, pchild)) {
		//print_char("bad client request:\n", buf, (int)nread);
		indicate_http_error(connptr, 400, "Bad Request",
			"detail",
			"Could not retrieve all the headers from "
			"the client.", NULL);
		goto done;
	}

	//after got server host name, then response client
	const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
	int len = (int)strlen(response);
	int nwrite;
	nwrite = send(fd, response, len, 0);
	if (nwrite != len) {
		log_message(LOG_ERR, "proxy_read_connect_req: error send response,\
			need send %d, real send %d", len, nwrite);
		goto done;
	}
	log_message(LOG_CONN, "Established connection to host \"%s\"", pchild->req.host);
	mitm_set_filter_mode(pchild);
	if (pchild->filter_res == FILTER_RESULT_PASS) {
		//passthrough mode, forward only
		if (set_passthrough_mode(pchild))
			goto done;
		return;
	}
	//read clientheello
	pchild->ev = event_new(pchild->mctx->base, fd,
		EV_READ, protossl_fd_readcb, pchild);
	event_add(pchild->ev, NULL);
	return;

done:
	evutil_closesocket(fd);
	clean_connection(pchild);//close this connection
	return;
}

//begin relaying the bytes between the two connections
static void relay_connection(struct child* pchild)
{
	struct conn_s* connptr = &pchild->conn;
	struct bufferevent* server = connptr->server_socket;
	struct bufferevent* client = connptr->client_socket;

	bufferevent_setcb(server, protohttp_bev_readcb, NULL, protossl_bev_eventcb, (void*)pchild);
	bufferevent_setcb(client, protohttp_bev_readcb, NULL, protossl_bev_eventcb, (void*)pchild);
	bufferevent_enable(client, EV_READ | EV_WRITE); 
	bufferevent_enable(server, EV_READ | EV_WRITE);
}

void on_connect_remote_server(struct child* pchild, int status)
{
	struct conn_s* connptr = &pchild->conn;
	struct bufferevent* server = connptr->server_socket;

	int port = connptr->port;
	char* host = pchild->req.host;
	if (status < 0) {
		log_message(LOG_INFO, "connect failed error \n");
		bufferevent_free(connptr->server_socket);
		connptr->server_socket = NULL;
		log_message(LOG_WARNING,
			"opensock: Could not establish a connection to %s:%d\n", host, port);

		indicate_http_error(connptr, 500, "Unable to connect",
			"detail",
			PACKAGE_NAME " "
			"was unable to connect to the remote web server.",
			"error", strerror(errno), NULL);
		send_http_error_message(connptr);
		return;
	}

	relay_connection(pchild);
	log_message(LOG_INFO,
		"Closed connection between local client and remote client,"
		"connection number is %d\n", pchild->mctx->childs_num);
}

static void server_eventcb(struct bufferevent* bev, short what, void* ctx)
{
	struct child* pchild = (struct child*)ctx;
	if (pchild->conn.dns_base) {
		evdns_base_free(pchild->conn.dns_base, 0);
		pchild->conn.dns_base = NULL;
	}

	if (what & BEV_EVENT_CONNECTED) {
		//connected with remote server
		log_message(LOG_INFO, "Connect %s okay\n", pchild->req.host);
		on_connect_remote_server(pchild, 0);
		return;
	}

	if (what & BEV_EVENT_TIMEOUT)
		return;

	//DNS query failed
	clean_connection(pchild);
}

static void on_new_connection(struct evconnlistener* listener,
	evutil_socket_t fd,
	struct sockaddr* sa, int socklen, void* user_data)
{
	struct mitm_ctx_st* mctx = (struct mitm_ctx_st*)user_data;
	struct child* pchild = malloc(sizeof(struct child));
	child_struct_init(pchild, mctx);

	pchild->conn.fd = fd;
	mctx->childs_num++;
	list_add_tail(&pchild->child_list, &mctx->child_list_head);

	pchild->conn.client_port = get_sockpeer_port(fd);

	//proxy_read_connect_req handle CONNECT request
	pchild->ev = event_new(pchild->mctx->base, fd,
		EV_READ, proxy_read_connect_req, pchild);
	event_add(pchild->ev, NULL);
}

/*
LEV_OPT_CLOSE_ON_FREE
If this option is set, the connection listener closes its underlying socket when you free it.

LEV_OPT_CLOSE_ON_EXEC
If this option is set, the connection listener sets the close-on-exec flag on the underlying listener socket. 
*/
int start_proxy_server(struct mitm_ctx_st* mctx, evconnlistener_cb cb)
{
	//set proxy server address
	struct sockaddr_in proxy_addr;
	char* ip = mctx->config->proxy_addr;
	int port = mctx->config->proxy_port;
	init_sockaddr_in(&proxy_addr, ip, port);

	struct evconnlistener* listener;
	listener = evconnlistener_new_bind(mctx->base, cb, (void*)mctx,
		LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC, -1,
		(struct sockaddr*)&proxy_addr,
		sizeof(proxy_addr));

	if (!listener) {
		printf("Could not create a listener!\n");
		return 1;
	}
	mctx->listener = listener;
	event_add(mctx->signal_event, NULL);

	printf("MITM proxy listening at %s:%d\n", ip, port);
	printf("(\"stop this proxy by press key: ctrl+c\")\n");
	return 0;
}
