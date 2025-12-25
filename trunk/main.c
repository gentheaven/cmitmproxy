#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mitm.h"

static char html_changed[] = "\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
<title>Changed content</title>\n\
</head>\n\
<body>\n\
<p><em>hello world.</em></p>\n\
</body>\n\
</html>\n\
";

/*
* test: open wechat client, and open a video
* video title will be change to "Albert"
*/

enum FILTER_RESULT cb_host_localhost(const char* host_name, void* arg)
{
	if(strstr(host_name, "qq.com")) {
		return FILTER_RESULT_SPLIT; //crack this website
	}
	return FILTER_RESULT_PASS; //forward only
}

int http_response(
	void* arg, http_info_t* http_ctx, //in
	char** out, size_t* out_len, FreeFunc* cb_free)
{
	//only care http response
	if(!http_ctx->response)
		return 0;

	//changed html content
	*out = html_changed;
	*out_len = strlen(html_changed);
	*cb_free = NULL; //no need free
	return 1;
}

const char weixin_host[] = "channels.weixin.qq.com";

int cb_cared(http_info_t* http_ctx, void* arg)
{
	if(!http_ctx->http_host || !http_ctx->http_content_type)
		return 0;

	//Host: channels.weixin.qq.com
	if(_strnicmp(http_ctx->http_host, weixin_host, strlen(weixin_host)))
		return 0;

	//Content-Type: text/html; charset=UTF-8\r\n
	if(_strnicmp("text/html", http_ctx->http_content_type, strlen("text/html")))
		return 0;

	//host is channels.weixin.qq.com, and Content-Type is text/html
	return 1;
}

int main(int argc, char** argv)
{
	int ret = -1;
	mitm_ctx* mitm = mitm_init(DEFAULT_PROXY_ADDR, DEFAULT_PROXY_PORT);
	if(!mitm)
		goto fail;
	//define filter system
	register_filter_cb_host(mitm, cb_host_localhost);
	register_filter_cb_cared(mitm, cb_cared);
	register_action_cb_http(mitm, http_response);

	char* app_arg = malloc(32);
	strcpy(app_arg, "hello world");
	mitm_run(mitm, app_arg); //main loop
	free(app_arg);
	ret = 0;
fail:
	mitm_exit(mitm);
	return ret;
}
