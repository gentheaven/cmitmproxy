#include <stdlib.h>
#include <string.h>

#include "mid.h"
#include "mid_priv.h"

static void fill_user_info(protohttp_ctx_t* http_ctx, http_info_t* phi);
static char* read_one_line(char* head, size_t len, size_t* offset);
static enum app_right proper_type(char* content_type);
static int parse_http_chunk(protohttp_ctx_t* http_ctx);

char* encode(enum compress_mode mode, char* buf, size_t buf_len, size_t* enc_len)
{
	char* enc = NULL;

	switch (mode) {
		case CMP_MODE_GZIP:
			enc = gzip_compress(buf, buf_len, enc_len);
			break;
		case CMP_MODE_DEFLATE:
			enc = raw_deflate_compress(buf, buf_len, enc_len);
			break;
		case CMP_MODE_BR:
			enc = br_compress(buf, buf_len, enc_len);
			break;
		default:
			return NULL;
	}
	return enc;
}

char* decode(enum compress_mode mode, char* buf, size_t buf_len, size_t* dec_len)
{
	char* dec = NULL;

	switch (mode) {
		case CMP_MODE_GZIP:
			dec = gzip_decompress(buf, buf_len, dec_len);
			break;
		case CMP_MODE_DEFLATE:
			dec = raw_deflate_decompress(buf, buf_len, dec_len);
			break;
		case CMP_MODE_BR:
			dec = br_decompress(buf, buf_len, dec_len);
			break;
		default:
			return NULL;
	}
	return dec;
}


///////////////////////////////
//http header parsing

void free_http_lines(protohttp_ctx_t* http_ctx)
{
	int i;
	if (http_ctx->total_lines) {
		for (i = 0; i < http_ctx->total_lines; i++) {
			free(http_ctx->lines[i]);
		}
		http_ctx->total_lines = 0;
	}
}

void free_http_req_lines(protohttp_ctx_t* http_ctx)
{
	int i;
	if (http_ctx->req_total_lines) {
		for (i = 0; i < http_ctx->req_total_lines; i++) {
			free(http_ctx->req_lines[i]);
		}
		http_ctx->req_total_lines = 0;
	}
}

void free_http_mitm(protohttp_ctx_t* http_ctx)
{
	//re-org to msg_body -> dec -> changed by app:out -> enc -> add header:chg_http
	if(http_ctx->multi_packet)
		free(http_ctx->msg_body);
	if(http_ctx->dec_msg)
		free(http_ctx->dec_msg);
	if(http_ctx->out && http_ctx->free_func)
		http_ctx->free_func(http_ctx->out);
	
	if(http_ctx->enc_msg)
		free(http_ctx->enc_msg);
	if (http_ctx->chg_http)
		free(http_ctx->chg_http);

	http_ctx->msg_body = NULL;
	http_ctx->chg_http = NULL;
	http_ctx->dec_msg = NULL;
	http_ctx->enc_msg = NULL;
	http_ctx->out = NULL;
	free_http_lines(http_ctx);
	free_http_req_lines(http_ctx);
}

void protohttp_free_http(protohttp_ctx_t* http_ctx)
{
	if(http_ctx->http_method) {
		free(http_ctx->http_method);
		http_ctx->http_method = NULL;
	}
	if(http_ctx->http_uri) {
		free(http_ctx->http_uri);
		http_ctx->http_uri = NULL;
	}
	if(http_ctx->http_host) {
		free(http_ctx->http_host);
		http_ctx->http_host = NULL;
	}
	if(http_ctx->http_content_type) {
		free(http_ctx->http_content_type);
		http_ctx->http_content_type = NULL;
	}
	if(http_ctx->http_status_code) {
		free(http_ctx->http_status_code);
		http_ctx->http_status_code = NULL;
	}
	if(http_ctx->http_status_text) {
		free(http_ctx->http_status_text);
		http_ctx->http_status_text = NULL;
	}
	if(http_ctx->http_content_length) {
		free(http_ctx->http_content_length);
		http_ctx->http_content_length = NULL;
	}
	if(http_ctx->http_transfer_encoding) {
		free(http_ctx->http_transfer_encoding);
		http_ctx->http_transfer_encoding = NULL;
	}
}

//reset parsing
void protohttp_reset_ctx(void* ctx)
{
	protohttp_ctx_t* http_ctx = (protohttp_ctx_t*)ctx;

	protohttp_free_http(http_ctx);
	
	free_http_mitm(http_ctx);

	struct proxy_mid_shared proxy_share_info;
	proxy_share_info = http_ctx->proxy_share_info;
	
	memset(http_ctx, 0, sizeof(protohttp_ctx_t));
	http_ctx->proxy_share_info = proxy_share_info;
}


void* protohttp_init_ctx(void* arg,
	cbfilter_by_http_header cb_cared,
	cb_http_response cb_response)
{
	protohttp_ctx_t* http_ctx = malloc(sizeof(protohttp_ctx_t));
	memset(http_ctx, 0, sizeof(protohttp_ctx_t));
	struct proxy_mid_shared* share = &http_ctx->proxy_share_info;

	share->arg = arg;
	share->cb_cared = cb_cared;
	share->cb_response = cb_response;
	return (void*)http_ctx;
}

//reset and free
void protohttp_free_ctx(void* ctx)
{
	if(!ctx)
		return;
	protohttp_ctx_t* http_ctx = (protohttp_ctx_t*)ctx;
	protohttp_reset_ctx(http_ctx);
	free(http_ctx);
}

/*
 * Returns a pointer to the first non-whitespace character in s.
 * Only space and tab characters are considered whitespace.
 */
char* util_skipws(const char* s)
{
	return (char*)s + strspn(s, " \t");
}

/*
 * Filter a single line of HTTP request headers.
 * Also fills in some context fields for logging.
 *
 * Returns NULL if the current line should be deleted from the request.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns 'line' if the line should be kept.
 */
char* protohttp_filter_request_header_line(
		const char* line, 
		protohttp_ctx_t* http_ctx)
{
	unsigned int remove_http_accept_encoding = 0;
	unsigned int remove_http_referer = 1;

	/* parse information for connect log */
	if (!http_ctx->http_method) {
		/* first line */
		char* space1, * space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1) {
			/* not HTTP */
			http_ctx->seen_req_header = 1;
			http_ctx->not_valid = 1;
		} else {
			http_ctx->http_method = malloc(space1 - line + 1);
			if (http_ctx->http_method) {
				memcpy(http_ctx->http_method, line, space1 - line);
				http_ctx->http_method[space1 - line] = '\0';
			}
			space1++;
			if (!space2) {
				/* HTTP/0.9 */
				http_ctx->seen_req_header = 1;
				space2 = space1 + strlen(space1);
			}
			http_ctx->http_uri = malloc(space2 - space1 + 1);
			if (http_ctx->http_uri) {
				memcpy(http_ctx->http_uri, space1, space2 - space1);
				http_ctx->http_uri[space2 - space1] = '\0';
			}
		}
	} else {
		/* not first line */
		char* newhdr;

		if (!http_ctx->http_host && !strncasecmp(line, "Host:", 5)) {
			http_ctx->http_host = strdup(util_skipws(line + 5));
			http_ctx->seen_keyword_count++;
		} else if (!http_ctx->http_content_length &&
				!strncasecmp(line, "Content-Length:", 15)) {
			http_ctx->http_content_length =
				strdup(util_skipws(line + 15));
		} else if (!strncasecmp(line, "Content-Type:", 13)) {
			http_ctx->http_content_type = _strdup(util_skipws(line + 13));
			http_ctx->seen_keyword_count++;
			/* Override Connection: keepalive and Connection: upgrade */
		} else if (!strncasecmp(line, "Connection:", 11)) {
			http_ctx->sent_http_conn_close = 1;
			newhdr = strdup("Connection: close");
			http_ctx->seen_keyword_count++;
			return newhdr;
			// @attention Always use conn ctx for opts, child ctx does not have opts, see the comments in pxy_conn_child_ctx
		} else if (remove_http_accept_encoding && !strncasecmp(line, "Accept-Encoding:", 16)) {
			http_ctx->seen_keyword_count++;
			return NULL;
		} else if (remove_http_referer && !strncasecmp(line, "Referer:", 8)) {
			http_ctx->seen_keyword_count++;
			return NULL;
			/* Suppress upgrading to SSL/TLS, WebSockets or HTTP/2 and keep-alive */
		} else if (!strncasecmp(line, "Upgrade:", 8) || !strncasecmp(line, "Keep-Alive:", 11)) {
			http_ctx->seen_keyword_count++;
			return NULL;
		} else if (line[0] == '\0') {
			http_ctx->seen_req_header = 1;
			if (!http_ctx->sent_http_conn_close) {
				newhdr = strdup("Connection: close\r\n");
				return newhdr;
			}
		}
	}

	return (char*)line;
}

//now only support peek http request, can't change it
int handle_req_data(char* http, size_t http_len, protohttp_ctx_t* http_ctx)
{
	//Content-Length: 1200\r\n
	if (!http_ctx->http_content_length)
		return 0;

	http_ctx->msg_body = http;
	http_ctx->msg_body_len = http_len;
	http_info_t* phi = http_ctx->phi;
	fill_user_info(http_ctx, phi);
	phi->response = 0;
	char* out;
	size_t out_len;
	http_ctx->free_func = NULL;
	struct proxy_mid_shared* share = &http_ctx->proxy_share_info;
	share->cb_response(share->arg, phi,
		&out, &out_len, &http_ctx->free_func);

	//request and response share it, so reset it
	free(http_ctx->http_content_length);
	http_ctx->http_content_length = NULL;

	http_ctx->msg_body_len = 0;
	http_ctx->msg_body_offset = 0;
	return 0;
}

int protohttp_filter_request_header(
	char* http, size_t http_len, protohttp_ctx_t* http_ctx)
{
	char* line;
	char* replace;
	size_t offset = 0;
	int line_num = 0;
	int changed = 0;
	while (!http_ctx->seen_req_header){
		line = read_one_line(http, http_len, &offset);
		if (!line)
			break;
		replace = protohttp_filter_request_header_line(line, http_ctx);
		if (!replace) {
			free(line); //remove this line
			changed = 1;
			continue;
		}

		if (replace == line) {
			http_ctx->req_lines[line_num] = line;
		} else if (replace) {
			http_ctx->req_lines[line_num] = replace;
			free(line); //replace this line
		}
		line_num++;
		if (line_num >= MAX_HTTP_HEAD_LINES) {
			printf("err: http request line number is more than 128 lines\n");
			break;
		}
	}

	http_ctx->req_total_lines = (line_num - 1);
	http_ctx->msg_body_offset = offset;
	http_ctx->msg_body = http + offset;
	http_ctx->msg_body_len = http_len - offset;

	return changed;
}

//Accept-Encoding: gzip, deflate, br\r\n
//Content-Encoding: br\r\n
enum compress_mode get_cmp_mode(char* str)
{
	enum compress_mode mode = CMP_MODE_PLAIN;
	if (!strncasecmp(str, "br", 2))
		mode = CMP_MODE_BR;
	else if (!strncasecmp(str, "gzip", 4))
		mode = CMP_MODE_GZIP;
	else if (!strncasecmp(str, "deflate", 7))
		mode = CMP_MODE_DEFLATE;
	return mode;
}
/*
 * Filter a single line of HTTP response headers.
 *
 * request:
 GET virtual_svg-icons-register.publishDJmRcesj.js HTTP/1.1\r\n
 Accept-Encoding: gzip, deflate, br\r\n

response:
Content-Encoding: br\r\n
Content-Length: 131323\r\n

Content-encoded entity body (br): 131323 bytes -> 413942 bytes

 *
 * Returns NULL if the current line should be deleted from the response.
 * Returns `line' if the line should be kept.
 */
static char* protohttp_filter_response_header_line(
		const char* line, protohttp_ctx_t* http_ctx,
		int* is_content_len)
{
	/* parse information for connect log */
	if (!http_ctx->http_status_code) {
		/* first line */
		char* space1, * space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1 || !!strncmp(line, "HTTP", 4)) {
			/* not HTTP or HTTP/0.9 */
			http_ctx->seen_resp_header = 1;
		}
		else {
			size_t len_code, len_text;
			if (space2) {
				len_code = space2 - space1 - 1;
				len_text = strlen(space2 + 1);
			}
			else {
				len_code = strlen(space1 + 1);
				len_text = 0;
			}
			http_ctx->http_status_code = malloc(len_code + 1);
			http_ctx->http_status_text = malloc(len_text + 1);
			memcpy(http_ctx->http_status_code, space1 + 1, len_code);
			http_ctx->http_status_code[len_code] = '\0';
			if (space2) {
				memcpy(http_ctx->http_status_text,
						space2 + 1, len_text);
			}
			http_ctx->http_status_text[len_text] = '\0';
		}
	}
	else {
		/* not first line */
		if (!http_ctx->http_content_length &&
				!strncasecmp(line, "Content-Length:", 15)) {
			http_ctx->http_content_length =
				strdup(util_skipws(line + 15));
			*is_content_len = 1;
		}
		else if (!strncasecmp(line, "Content-Type:", 13)) {
			http_ctx->http_content_type = _strdup(util_skipws(line + 13));
			http_ctx->seen_keyword_count++;
		}
		else if (!strncasecmp(line, "Content-Encoding:", 17)) {
			//Content-Encoding: br\r\n
			http_ctx->cmp_mode = get_cmp_mode(util_skipws(line + 17));
			http_ctx->seen_keyword_count++;
		}
		else if (!strncasecmp(line, "Transfer-Encoding:", 18)) {
			//Transfer-Encoding: chunked\r\n
#ifdef SUPPORT_CHUNK
			http_ctx->http_transfer_encoding = _strdup(util_skipws(line + 18));
			if (!strncasecmp(http_ctx->http_transfer_encoding, "chunked", 7))
				http_ctx->chunked = 1;
#endif
		}
		else if (
				/* HPKP: Public Key Pinning Extension for HTTP
				 * (draft-ietf-websec-key-pinning)
				 * remove to prevent public key pinning */
				!strncasecmp(line, "Public-Key-Pins:", 16) ||
				!strncasecmp(line, "Public-Key-Pins-Report-Only:", 28) ||
				/* HSTS: HTTP Strict Transport Security (RFC 6797)
				 * remove to allow users to accept bad certs */
				!strncasecmp(line, "Strict-Transport-Security:", 26) ||
				/* Expect-CT: Expect Certificate Transparency
				 * (draft-ietf-httpbis-expect-ct-latest)
				 * remove to prevent failed CT log lookups */
				!strncasecmp(line, "Expect-CT:", 10) ||
				/* Alternate Protocol
				 * remove to prevent switching to QUIC, SPDY et al */
				!strncasecmp(line, "Alternate-Protocol:", 19) ||
				/* Upgrade header
				 * remove to prevent upgrading to HTTPS in unhandled ways,
				 * and more importantly, WebSockets and HTTP/2 */
				!strncasecmp(line, "Upgrade:", 8)) {
			return NULL;
		}
		else if (line[0] == '\0') {
			http_ctx->seen_resp_header = 1;
		}
	}

	return (char*)line;
}

//suppose one line max is 1024 bytes
static char* read_one_line(char* head, size_t len, size_t* offset)
{
	char* cur = head + *offset;
	size_t cur_len = len - *offset;
	char* out = malloc(1024);

	int result = _snscanf(cur, cur_len, "%1023[^\n]", out);
	if (result != 1) {
		free(out);
		return NULL;
	}

	size_t out_len = strlen(out);
	out[out_len - 1] = 0; //remove \n
	*offset = *offset + out_len + 1; //CRLF
	return out;
}

/*
 * in:
 http_header/http_len: HTTP response header

out:
http_ctx: fill fields
 * return if changed http header
 */
static int
protohttp_filter_response_header(
		char* http_header, size_t http_len, //in
		protohttp_ctx_t* http_ctx) //out
{
	char* line;
	char* replace;
	int line_num = 0;
	int is_content_len = 0; //Content-Length:
	int changed = 0;

	size_t offset = 0;
	http_ctx->cmp_mode = CMP_MODE_PLAIN;
	while (!http_ctx->seen_resp_header) {
		line = read_one_line(http_header, http_len, &offset);
		if (!line)
			break;
		replace = protohttp_filter_response_header_line(line, http_ctx, &is_content_len);
		if (!replace) {
			free(line); //remove this line
			changed = 1;
			continue;
		}

		if (is_content_len) {
			is_content_len = 0; //Content-Length: record index
			http_ctx->cl_index = line_num;
		}
		//keep or change, now only record this line
		if (replace == line) {
			http_ctx->lines[line_num] = line;
		} else {
			http_ctx->lines[line_num] = replace;
			free(line); //replace this line
		}
		line_num++;
		if (line_num >= MAX_HTTP_HEAD_LINES) {
			printf("err: http response line number is more than 128 lines\n");
			break;
		}
	}
	http_ctx->msg_body_offset = offset;
	http_ctx->total_lines = (line_num - 1);
	return changed;
}

//Content-Length: 615\r\n
void change_Content_Length(char** out, size_t new_len)
{
	char* ori = *out;
	char* new_content = malloc(32);
	sprintf(new_content, "Content-Length: %lld", new_len);
	*out = new_content;
	free(ori);
}

void http_add_chunks(protohttp_ctx_t* http_ctx, 
	char* changed_buf, size_t head_offset,
	char* msg, size_t msg_len)
{
	size_t offset = head_offset;
	
	//add chuncked header
	//len \r\n data \r\n
	//len
	char len_field[16];
	sprintf(len_field, "%zx", msg_len);
	size_t len_bytes = strlen(len_field);
	memcpy(changed_buf + offset, len_field, len_bytes);
	offset += len_bytes;

	//\r\n
	memcpy(changed_buf + offset, "\r\n", 2);
	offset += 2;

	//data
	memcpy(changed_buf + offset, msg, msg_len);
	offset += msg_len;

	//\r\n
	memcpy(changed_buf + offset, "\r\n", 2);
	offset += 2;

	//add tail: 0\r\n\r\n
	memcpy(changed_buf + offset, "0\r\n\r\n", 5);
	offset += 5;

	http_ctx->chg_http = changed_buf;
	http_ctx->chg_http_len = offset;
	printf("organize_new_http chunked, total len=%lld, msg_len=%lld\n",
		http_ctx->chg_http_len, msg_len);
}

//reorg http header and body to http_ctx->chg_http[chg_http_len]
//input: phi->http_content and  phi->http_content_length
void organize_new_http(int changed, protohttp_ctx_t* http_ctx)
{
	http_info_t* phi = http_ctx->phi;

	char* msg = phi->http_content;
	size_t msg_len = phi->http_content_length;
	if (changed && !http_ctx->chunked) {
		change_Content_Length(
			&http_ctx->lines[http_ctx->cl_index], msg_len);
	}

	size_t change_buf_size = 2048;
	change_buf_size += msg_len; //changed html len
	char* changed_buf = malloc(change_buf_size);

	//http header
	int i;
	size_t offset = 0;
	size_t line_len;
	char* cur_line;
	for (i = 0; i < http_ctx->total_lines; i++) {
		cur_line = http_ctx->lines[i];
		line_len = strlen(cur_line);
		sprintf(changed_buf + offset, "%s\r\n", cur_line);
		offset = offset + line_len + 2;
	}
	sprintf(changed_buf + offset, "\r\n");
	offset += 2;

	if(http_ctx->chunked){
		http_add_chunks(http_ctx, changed_buf, offset, msg, msg_len);
		return;
	}
	//msg body
	memcpy(changed_buf + offset, msg, msg_len);
	http_ctx->chg_http = changed_buf;
	http_ctx->chg_http_len = offset + msg_len;
	printf("organize_new_http, total len=%lld, msg_len=%lld\n", http_ctx->chg_http_len, msg_len);
}

//http_ctx->cmp_mode != CMP_MODE_PLAIN
//return if html body changed by app
int decom_content_call_app(protohttp_ctx_t* http_ctx)
{
	http_info_t* phi = http_ctx->phi;

	//decompression
	http_ctx->dec_msg = decode(http_ctx->cmp_mode,
			http_ctx->msg_body, http_ctx->msg_body_len, &http_ctx->dec_msg_len);
	if (!http_ctx->dec_msg) {
		//decompression failed, keep ori
		phi->http_content = http_ctx->msg_body;
		phi->http_content_length = http_ctx->msg_body_len;
		organize_new_http(0, http_ctx);
		return 1;
	}

	//send decode data to app
	phi->http_content = http_ctx->dec_msg;
	phi->http_content_length = http_ctx->dec_msg_len;
	int msg_body_changed = 0;
	http_ctx->out = NULL;
	http_ctx->free_func = NULL;
	struct proxy_mid_shared* share = &http_ctx->proxy_share_info;
	msg_body_changed = share->cb_response(
		share->arg, phi,
		&http_ctx->out, &http_ctx->out_len, &http_ctx->free_func);
	if(!msg_body_changed)
		http_ctx->out = NULL;

	if (msg_body_changed) {
		http_ctx->enc_msg = encode(http_ctx->cmp_mode,
				http_ctx->out, http_ctx->out_len, &http_ctx->enc_msg_len);
		//organize http header and message body to new buffer
		phi->http_content = http_ctx->enc_msg;
		phi->http_content_length = http_ctx->enc_msg_len;
	} else { //used original content of server to client
		phi->http_content = http_ctx->msg_body;
		phi->http_content_length = http_ctx->msg_body_len;
	}

	organize_new_http(msg_body_changed, http_ctx);
	return 1;
}

/*
 * here: http_ctx->get_all = 1
 * return 
 *	0: not change
 *	1: changed
*/
int send_packet_to_app(protohttp_ctx_t* http_ctx)
{
	http_info_t* phi = http_ctx->phi;

	int msg_body_changed = 0;
	http_ctx->out = NULL;
	if (http_ctx->cmp_mode == CMP_MODE_PLAIN) {
		struct proxy_mid_shared* share = &http_ctx->proxy_share_info;
		msg_body_changed = share->cb_response(
			share->arg, phi,
			&http_ctx->out, &http_ctx->out_len, &http_ctx->free_func);

		if (http_ctx->right == APP_RIGHT_PEEK) {
			//app only have read right
			return 0;
		}

		if (msg_body_changed) {
			phi->http_content = http_ctx->out;
			phi->http_content_length = http_ctx->out_len;
		} else {
			phi->http_content = http_ctx->msg_body;
			phi->http_content_length = http_ctx->msg_body_len;
		}
		organize_new_http(msg_body_changed, http_ctx);
		msg_body_changed = 1;
	} else {
		//decom_content_call_app internal call organize_new_http
		msg_body_changed = decom_content_call_app(http_ctx);
	}
	return msg_body_changed;
}

//server keep send http message body without http header
//http_ctx->cared = 1, msg_body = malloc(http_ctx->content_length);
enum packet_handle_result save_packet(char* http, size_t http_len, protohttp_ctx_t* http_ctx)
{
	//saved message body
	size_t copied;
	if ((http_ctx->msg_body_len + http_len) >= http_ctx->content_length)
		copied = http_ctx->content_length - http_ctx->msg_body_len;
	else
		copied = http_len;

	memcpy(http_ctx->msg_body + http_ctx->msg_body_len, http, copied);
	http_ctx->msg_body_len += copied;

	if(http_ctx->chunked) {
		http_ctx->get_all = parse_http_chunk(http_ctx);
		return PACKET_DISCARD;
	}

	if (http_ctx->msg_body_len < http_ctx->content_length) {
		if (http_ctx->right == APP_RIGHT_PEEK)
			return PACKET_FORWARD;
		return PACKET_DISCARD;
	}
	http_ctx->get_all = 1;
	return PACKET_CHANGE;
}

//http response has only one packet
void send_changed_http(int msg_body_changed, protohttp_ctx_t* http_ctx)
{
	//header max 2048 bytes
	size_t change_buf_size = 2048;
	if (msg_body_changed)
		change_buf_size += http_ctx->out_len; //changed html len
	else
		change_buf_size += http_ctx->msg_body_len; //ori html len

	char* changed_buf = malloc(change_buf_size);
	//add http header
	int i;
	size_t offset = 0;
	size_t line_len;
	char* cur_line;
	for (i = 0; i < http_ctx->total_lines; i++) {
		cur_line = http_ctx->lines[i];
		line_len = strlen(cur_line);
		sprintf(changed_buf + offset, "%s\r\n", cur_line);
		offset = offset + line_len + 2;
	}
	sprintf(changed_buf + offset, "\r\n");
	offset += 2;

	if(http_ctx->chunked){
		if(msg_body_changed)
			http_add_chunks(http_ctx, changed_buf, offset, http_ctx->out, http_ctx->out_len);
		else
			http_add_chunks(http_ctx, changed_buf, offset, http_ctx->msg_body, http_ctx->msg_body_len);
		return;
	}

	if (msg_body_changed) {//changed content
		memcpy(changed_buf + offset, http_ctx->out, http_ctx->out_len);
		change_buf_size = offset + http_ctx->out_len;
	} else { //original content
		memcpy(changed_buf + offset, http_ctx->msg_body, http_ctx->msg_body_len);
		change_buf_size = offset + http_ctx->msg_body_len;
	}
	http_ctx->chg_http = changed_buf;
	http_ctx->chg_http_len = change_buf_size;
	
	if (msg_body_changed && http_ctx->free_func) {
		http_ctx->free_func(http_ctx->out);
		http_ctx->out = NULL;
	}
}

//only called by first see http respone header
static void fill_user_info(protohttp_ctx_t* http_ctx, http_info_t* phi)
{
	phi->http_content = http_ctx->msg_body;
	if (http_ctx->http_content_length) {
		http_ctx->content_length = atol(http_ctx->http_content_length);
		phi->http_content_length = http_ctx->content_length;
		if (http_ctx->msg_body_len < http_ctx->content_length) {
			//msg_body_len: message body len of first packet
			//http_content_length: all len of this body
			//now, get_all = 0, need get more http content
			http_ctx->get_all = 0;
		} else {
			http_ctx->get_all = 1;
		}
	} else if (http_ctx->chunked) {
		//Transfer-Encoding: chunked\r\n
		phi->http_content_length = http_ctx->msg_body_len;
		http_ctx->content_length = MAX_CHUNCK_LEN;
	} else {
		http_ctx->get_all = 1; //no "Content-Length" field, suppose only one packet
		phi->http_content_length = http_ctx->msg_body_len;
	}

	phi->http_content_type = http_ctx->http_content_type;
	phi->http_host = http_ctx->http_host;
	phi->http_method = http_ctx->http_method;
	phi->http_uri = http_ctx->http_uri;
}

/*
 * http_ctx->cared = 1
 now, only see http header, No complete information has been obtained
 so save current message

 http header: http_ctx->lines[i]
 http_ctx->msg_body: The previously pointed address will be released
 here point to new address
 */
void save_msg_body(protohttp_ctx_t* http_ctx, http_info_t* phi)
{
	char* all = malloc(http_ctx->content_length);
	if (http_ctx->msg_body_len) {
		memcpy(all, http_ctx->msg_body, http_ctx->msg_body_len);
	}
	http_ctx->msg_body = all;
	phi->http_content = all;
	http_ctx->multi_packet = 1;
}

char* find_crlf(char* buf, size_t buf_len)
{
	size_t offset = 0;
	char* cur = buf;
	while (offset < buf_len) {
		if (*cur == '\r' || *cur == '\n') {
			return cur;
		}
		cur++;
		offset++;
	}

	return NULL;
}

/* Transfer-Encoding: chunked\r\n
in: http_ctx->msg_body;
http_ctx->msg_body_len;
out:
if reach end, return 1;
return 0 otherwise
*/
int parse_http_chunk(protohttp_ctx_t* http_ctx)
{
	int chunk_len = 0;
	size_t chunk_bytes;

	char* head = http_ctx->msg_body;
	char* cur = head;
	int cur_len = (int)http_ctx->msg_body_len;

	char* all = malloc(MAX_CHUNCK_LEN);
	size_t all_len = 0;

	//len[chunk_bytes] \r\n chunk_content[chunk_len]  \r\n
	//end: 0\r\n\r\n
	char* tail;
	char c;
	size_t offset;
	while (cur_len > 0) {
		tail = find_crlf(head, cur_len);
		if (!tail) {//error
			free(all);
			return 0;
		}
		//get chunk len
		c = *tail;
		*tail = 0;
		sscanf(head, "%x", &chunk_len);
		chunk_bytes = strlen(head);
		*tail = c;

		if (!chunk_len) {
			//end: 0\r\n\r\n
			if(http_ctx->multi_packet) {
				//free old, old content includes chunk header
				free(http_ctx->msg_body);
			}
			http_ctx->msg_body = all;
			http_ctx->msg_body_len = all_len;
			return 1;
		}

		memcpy(all + all_len, head + chunk_bytes + 2, chunk_len);
		all_len = all_len + chunk_len;

		//find next
		offset = chunk_bytes + 2 + chunk_len + 2;
		head = head + offset;
		cur_len = (int)(cur_len - offset);
	}

	//only support all chunks with one packet
	free(all);
	return 0;
}

/*
if HTTP request has message body,
then this request is split into two packets by libevent.
first is HTTP header; 
second is message body like JSON data. has_req_content = 1

if no message body, has_req_content = 0
*/
enum packet_handle_result protohttp_handle_request(char* http, size_t http_len, protohttp_ctx_t* http_ctx)
{
	if (http_ctx->seen_req_header) {
		http_ctx->seen_req_header = 0; //trigger for next request header parse
		if(!http_ctx->has_req_content)
			return PACKET_FORWARD;

		//only cared: text/xxx, application/json, application/javascript
		enum app_right right = proper_type(http_ctx->http_content_type);
		if(right == APP_RIGHT_PEEK)
			return PACKET_FORWARD;
		
		handle_req_data(http, http_len, http_ctx);
		http_ctx->has_req_content = 0;
	} else {
		//first see http request header
		protohttp_reset_ctx(http_ctx);
		protohttp_filter_request_header(http, http_len, http_ctx);
		if(http_ctx->http_content_length)
			http_ctx->content_length = atol(http_ctx->http_content_length);
		else
			http_ctx->content_length = 0;
		//msg_body_len = 0(this packet has only HTTP header) and
		//content_length != 0, so second packet is exist
		if(!http_ctx->msg_body_len && http_ctx->content_length)
			http_ctx->has_req_content = 1;
	}
	return PACKET_FORWARD;
}

enum packet_handle_result protohttp_handle_response_left(
		char* http, size_t http_len, protohttp_ctx_t* http_ctx)
{
	enum packet_handle_result change = PACKET_FORWARD;

	if (http_ctx->get_all) {
		//In some cases(e.g. chunk), 
		//the length of the network packet is unknown, so set get_all=1,
		//and it is simply ignored
		return PACKET_FORWARD;
	}

	if (http_ctx->cared) {
		//if cared and more than one packet
		change = save_packet(http, http_len, http_ctx);
		if (!http_ctx->get_all)
			return change;

		int ret = send_packet_to_app(http_ctx);
		if(!ret)
			return PACKET_FORWARD;
		if (http_ctx->right == APP_RIGHT_PEEK)
			return PACKET_FORWARD; //app only peek content, not change it
		return PACKET_CHANGE;
	} else {
		//not cared
		return PACKET_FORWARD;
	}
	return PACKET_FORWARD;
}

//here http_ctx->cared = 1, handle http body, this is first http response
enum packet_handle_result handle_response_first_body(
	protohttp_ctx_t* http_ctx, int header_changed)
{
	http_info_t* phi = http_ctx->phi;
	enum packet_handle_result ret = PACKET_FORWARD;

	int msg_body_changed = 0;
	if (http_ctx->get_all) {
		http_ctx->out = NULL;
		http_ctx->free_func = NULL;
		//http response: only one packet
		if (http_ctx->cmp_mode == CMP_MODE_PLAIN) {
			struct proxy_mid_shared* share = &http_ctx->proxy_share_info;
			msg_body_changed = share->cb_response(
					share->arg, phi,
					&http_ctx->out, &http_ctx->out_len, &http_ctx->free_func);
			if (!msg_body_changed)
				http_ctx->out = NULL;
		} else {
			msg_body_changed = decom_content_call_app(http_ctx);
			if(msg_body_changed)
				return PACKET_CHANGE;
			return PACKET_FORWARD;
		}
	} else {
		/*only get part of messsage body, save it to new memory,
		  after got all messages, then send it.
		  here, msg_body_changed = 0, not free http_ctx->lines for future use
		  */
		save_msg_body(http_ctx, phi);
		if (http_ctx->right == APP_RIGHT_PEEK)
			return PACKET_FORWARD; //app only peek content, not change it
		return PACKET_DISCARD; //app may change content, so discard it
	}

	if (msg_body_changed && !http_ctx->chunked) {
		change_Content_Length(
				&http_ctx->lines[http_ctx->cl_index], http_ctx->out_len);
	}

	if (msg_body_changed || header_changed) {
		send_changed_http(msg_body_changed, http_ctx);
		ret = PACKET_CHANGE;
	} else { //keep original
		ret = PACKET_FORWARD;
	}

	return ret;
}

enum app_right proper_type(char* content_type)
{
	if(!content_type)
		return APP_RIGHT_PEEK;

	//text/xxx, application/json, application/javascript
	if(strstr(content_type, "text/"))
		return APP_RIGHT_MAY_MODIFY;

	if(!strncasecmp(content_type, "application/json",
		strlen("application/json")))
		return APP_RIGHT_MAY_MODIFY;

	if(!strncasecmp(content_type, "application/javascript",
		strlen("application/javascript")))
		return APP_RIGHT_MAY_MODIFY;

	return APP_RIGHT_PEEK;
}

//here, had cracked this traffic, and app called register_action_cb_http()
enum app_right judge_app_right(protohttp_ctx_t* http_ctx)
{
	enum app_right right = APP_RIGHT_PEEK;
	//no 2nd filter
	if (!http_ctx->proxy_share_info.cb_cared)
		return APP_RIGHT_PEEK;

	//app not cared this traffic
	if(!http_ctx->cared)
		return APP_RIGHT_PEEK;

	return proper_type(http_ctx->http_content_type);
}

enum packet_handle_result protohttp_handle_response_first(
		char* http, size_t http_len, protohttp_ctx_t* http_ctx)
{
	enum packet_handle_result change = PACKET_FORWARD;

	//1. peek for HTTP header, split to multi-lines, collect useful info
	int header_changed = 0;
	header_changed = protohttp_filter_response_header(
			http, http_len, http_ctx);

	if (!http_ctx->seen_resp_header) {
		return PACKET_FORWARD;
	}

	http_ctx->msg_body = http + http_ctx->msg_body_offset;
	http_ctx->msg_body_len = http_len - http_ctx->msg_body_offset;

	//2. handle chunk
	if (http_ctx->chunked) {
		http_ctx->get_all = parse_http_chunk(http_ctx);
	}

	//3. if app cared this traffic
	http_info_t* phi = http_ctx->phi;
	fill_user_info(http_ctx, phi);
	phi->response = 1;

	//default cared this https traffic
	struct proxy_mid_shared* share = &http_ctx->proxy_share_info;
	if (share->cb_cared) {
		http_ctx->cared = share->cb_cared(phi, share->arg);
		http_ctx->right = judge_app_right(http_ctx);
	} else {
		http_ctx->cared = 1;
		http_ctx->right = APP_RIGHT_PEEK;
	}

	if (!http_ctx->cared) {
		return PACKET_FORWARD;
	}

	//4. here http_ctx->cared = 1, handle http body
	change = handle_response_first_body(http_ctx, header_changed);
	return change;
}

/*
in:
c2s = 1: client to server, http request, not support change content now
c2s = 0: server to client, http response

return:
1, if changed http content, include header and message body
0, if not changed
*/
enum packet_handle_result protohttp_handle(
	int c2s, char* http, size_t http_len, void* ctx,
	char** out, size_t* out_len)
{
	protohttp_ctx_t* http_ctx = (protohttp_ctx_t*)ctx;
	http_ctx->phi = &http_ctx->http_info;
	enum packet_handle_result ret = PACKET_FORWARD;
	*out = NULL;
	*out_len = 0;

	//cliet to server: http request, not change request content
	if(c2s) {
		ret = protohttp_handle_request(http, http_len, http_ctx);
		return PACKET_FORWARD;
	}	

	//server to client: http response
	if (http_ctx->seen_resp_header) {
		//forward left http message body
		ret =  protohttp_handle_response_left(http, http_len, http_ctx);
	} else {
		http_ctx->seen_req_header = 0; //trigger for next request header parse
		ret = protohttp_handle_response_first(http, http_len, http_ctx);
	}

	*out = http_ctx->chg_http;
	*out_len = http_ctx->chg_http_len;
	return ret;
}

