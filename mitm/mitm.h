#ifndef MITM_H
#define MITM_H

#ifdef MITMLIBRARY_EXPORTS
#define MITMLIBRARY_API extern __declspec(dllexport)
#else
#define MITMLIBRARY_API extern __declspec(dllimport)
#endif

#define DEFAULT_PROXY_ADDR "127.0.0.1"
#define DEFAULT_PROXY_PORT 8080

/* filter */
enum WORK_MODE {
    WORK_MODE_FORWARD = 0, //HTTPS proxy
    WORK_MODE_MITM //mitm proxy
};

#define DEFAULT_WORK_MODE WORK_MODE_MITM

enum FILTER_RESULT {
    FILTER_RESULT_PASS = 0, //forward only
    FILTER_RESULT_SPLIT, //decrypt https traffic
};
#define DEFAULT_FILTER_RESULT FILTER_RESULT_SPLIT

//user need know:
/*
original http header:
GET /favicon.ico HTTP/1.1\r\n
Host: localhost\r\n
Content-Type: text/html\r\n
Content-Length: 615\r\n


after parse:

http_method: GET
http_uri: /favicon.ico
http_host: localhost
http_content_type: text/html
http_content_length: 615 (if not compressed)

http_content[http_content_length]
*/
typedef struct http_info {
	//http request or response
	int response; //response=0, http requst; response=1, http response

	//http header
	char* http_method;
	char* http_uri;
	char* http_host;
	char* http_content_type;

	//http body
	char* http_content;
	size_t http_content_length;
}http_info_t;

//this is called before TLS cracked
typedef enum FILTER_RESULT (*cbfilter_by_host)(const char* host_name, void* arg);

/*
	if need change content, should call register_filter_cb_cared();
	and cbfilter_by_http_header() return 1 if want change some specified content.

	this is called after TLS cracked.
	when proxy got first http response packet,
	after proxy parsed http response header, will call this function

	app tell proxy: app need peek or modify http content
	return 1, if want to modify it
	return 0, just peek
*/
typedef int (*cbfilter_by_http_header)(http_info_t *phi, void* arg);

typedef void (*FreeFunc)(void*);
/*
* in:
       arg: in/out used for app
	   info: http info

   out: 
        if changed html content, put changes to out[out_len]
		free_func:
			proxy will call  cb_free(out) after use it
			if cb_free is NULL, proxy not free
		e.g.
		*cb_free = NULL, proxy not free memory;
		*cb_free = free, proxy will call free(out)
return:
    if changed html content, return 1; 
    otherwise return 0
*/
typedef int (*cb_http_response)(
	void* arg, http_info_t* info, //in
	char** out, size_t* out_len, FreeFunc* cb_free); //out

typedef struct config_s CONFIG_S;
typedef struct mitm_ctx_st mitm_ctx;

#ifdef __cplusplus
extern "C" {
#endif

MITMLIBRARY_API
	mitm_ctx* mitm_init(char* ip, unsigned short port);

MITMLIBRARY_API
	void mitm_exit(struct mitm_ctx_st* ctx);

//arg: in/out used for app
MITMLIBRARY_API
	int mitm_run(struct mitm_ctx_st* ctx, void* arg);

MITMLIBRARY_API
	void mitm_set_work_mode(mitm_ctx* ctx, enum WORK_MODE mode);

//filter by hostname
MITMLIBRARY_API
	void register_filter_cb_host(mitm_ctx* ctx, cbfilter_by_host cbfunc);

MITMLIBRARY_API
	void register_filter_cb_cared(mitm_ctx* ctx, cbfilter_by_http_header cbfunc);

/* action when got http request/response */
MITMLIBRARY_API
	void register_action_cb_http(mitm_ctx* ctx, cb_http_response on_response);

//////////////////////////////////////////////////////////////////////////////////
//tools for regex

//callback function
//call this function when match
//head: buffer head
//list: app in-out parameter
typedef int (*regex_on_match)(char* head,
	size_t item_offset, size_t item_len, void* list);

/* match 'regex' at str
 if find_all is 1, find all matches
 else only find first

 return match count
 return negatvie if error
*/
MITMLIBRARY_API
	int regex_match(char* regex, char* str, unsigned int str_len,
		int find_all,
		regex_on_match on_match,
		void* list);

/*
* regex replace
* reg_extend_flag = 0, not set PCRE2_SUBSTITUTE_EXTENDED
* reg_extend_flag = 1, set PCRE2_SUBSTITUTE_EXTENDED
* 
*
* out: chg_content[chg_len]
*	chg_len: in/out, 
		input chg_len = sizeof(chg_content)
		output chg_len = The actual number of bytes output
* 
 return match count
 return negatvie if error
*/
MITMLIBRARY_API
	int regex_replace(char* content, unsigned int content_len,
		char* regex_match, char* regex_replace,
		char* chg_content, size_t* chg_len, int reg_extend_flag);

#ifdef __cplusplus
}
#endif

#endif
