#ifndef MID_H
#define MID_H

/*
app: Transaction Logic
	e.g. sample.c

mid: Parse HTTP header
	compress.c: Accept-Encoding: gzip, deflate, br
	pcre2lib.c: regex tools

	mid.c: HTTP header parsing

proxy: Crack HTTPs
	proxy.c: http/https proxy
	mitm.c: The part where the proxy interacts with the application

	protossl.c: libevent, Bufferevents and SSL
	https://libevent.org/libevent-book/Ref6a_advanced_bufferevents.html

	ssl.c: openssl encapsulation

public: 
	tools.c: useful tools
*/

#include <stdio.h>
#include "mitm.h"

//#define SUPPORT_CHUNK //Transfer-Encoding: chunked\r\n

#define MAX_CHUNCK_LEN (64 * 1024)
#define MAX_HTTP_LINE_BYTES 1024
#define MAX_HTTP_HEAD_LINES 128

enum packet_handle_result {
	PACKET_FORWARD = 0, //keep original, just forward
	PACKET_CHANGE, //mitm or app change content
	PACKET_DISCARD //discard this packet
};

//return mid ctx
extern void* protohttp_init_ctx(void* arg,
	cbfilter_by_http_header cb_cared,
	cb_http_response cb_response);

//clean
extern void protohttp_free_ctx(void* ctx);

/*
in:
	c2s = 1: client to server, http request
	c2s = 0: server to client, http response
	http[http_len]: http header and content
	ctx: mid ctx

out:
	out[out_len] if changed http

return:
	1, if changed http content, include header and message body
	0, if not changed
*/
extern enum packet_handle_result protohttp_handle(
	int c2s, char* http, size_t http_len, void* ctx,
	char** out, size_t* out_len);

#endif