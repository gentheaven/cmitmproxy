#ifndef MID_PRIV_H
#define MID_PRIV_H

#define strncasecmp _strnicmp
#define strcasecmp  _stricmp
#define strdup _strdup

//Accept-Encoding: gzip, deflate, br\r\n
enum compress_mode {
	CMP_MODE_PLAIN = 0, //no compressed
	CMP_MODE_GZIP,
	CMP_MODE_DEFLATE,
	CMP_MODE_BR
};

/*
suppose had cracked this https;
if
	1. app call register_filter_cb_cared(),
	2. this web is app cared
	3. HTTP Content-Type is text/xxx, application/json, application/javascript
then app could modify content.

otherwise:
	The application can only view the data but not modify it
*/
enum app_right {
	APP_RIGHT_PEEK = 0, //default
	APP_RIGHT_MAY_MODIFY //app could modify content
};


struct proxy_mid_shared{
	cbfilter_by_http_header cb_cared;
	cb_http_response cb_response; //http response
	void* arg;
};

typedef struct protohttp_ctx {
	unsigned int seen_req_header : 1; /* 0 until request header complete */
	unsigned int seen_resp_header : 1;  /* 0 until response hdr complete */
	unsigned int sent_http_conn_close : 1;   /* 0 until Conn: close sent */
	unsigned int ocsp_denied : 1;                /* 1 if OCSP was denied */

	/* log strings from HTTP request */
	char* http_method;
	char* http_uri;
	char* http_host;
	char* http_content_type;

	/* log strings from HTTP response */
	char* http_status_code;
	char* http_status_text;
	char* http_content_length;
	char* http_transfer_encoding;

	unsigned int not_valid : 1;    /* 1 if cannot find HTTP on first line */
	unsigned int seen_keyword_count;
	long long unsigned int seen_bytes;

	//mitm
	enum app_right right;

	//split http header
	//request
	char* req_lines[MAX_HTTP_HEAD_LINES]; //request
	int req_total_lines; //request
	int has_req_content; //content_length > msg_body_len, set it

	//response
	char* lines[MAX_HTTP_HEAD_LINES]; //response
	int total_lines; //response
	int cl_index; //Content-Length index
	size_t msg_body_offset; //message body offset

	char* msg_body; //ori content, proxy handle it
	size_t msg_body_len; //current body length
	size_t content_length; //atol(http_content_length)
	enum compress_mode cmp_mode; //compress mode, default is CMP_MODE_PLAIN(0)
	int chunked; //Transfer-Encoding: chunked\r\n
	int cared; //if app cared this content
	int get_all; //if got all http content, set 1
	int multi_packet; //if mesage body include more than one packet

	//if cmp_mode != CMP_MODE_PLAIN
	char* dec_msg;
	size_t dec_msg_len;
	char* enc_msg;
	size_t enc_msg_len;
	char* chg_http;
	size_t chg_http_len;

	//app fill it
	char* out;
	size_t out_len;
	FreeFunc free_func;

	http_info_t* phi; //Point to Http Info
	//shared with proxy
	struct proxy_mid_shared proxy_share_info;
	//export to app
	http_info_t http_info;
} protohttp_ctx_t;

//compress
extern char* encode(enum compress_mode mode, char* buf, size_t buf_len, size_t* enc_len);
extern char* decode(enum compress_mode mode, char* buf, size_t buf_len, size_t* dec_len);

extern char* br_compress(char* buf, size_t buf_len, size_t* out_len);
extern char* br_decompress(char* buf, size_t buf_len, size_t* out_len);

extern char* gzip_compress(char* src, size_t src_len, size_t* dst_len);
extern char* gzip_decompress(char* src, size_t src_len, size_t* dst_len);

extern char* raw_deflate_compress(char* src, size_t src_len, size_t* dst_len);
extern char* raw_deflate_decompress(char* src, size_t src_len, size_t* dst_len);

//reset mid
extern void protohttp_reset_ctx(void* ctx);

#endif
