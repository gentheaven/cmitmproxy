#include <stdio.h>

#include "proxy.h"
#include "libnet.h"

struct mitm_ctx_st* mitm_ctx_init(void)
{
	struct mitm_ctx_st* ctx;
	ctx = malloc(sizeof(struct mitm_ctx_st));
	memset(ctx, 0, sizeof(struct mitm_ctx_st));
	INIT_LIST_HEAD(&ctx->child_list_head);
	return ctx;
}

void mitm_set_work_mode(mitm_ctx* ctx, enum WORK_MODE mode)
{
	ctx->mode = mode;
}

void mitm_ctx_exit(mitm_ctx* mctx)
{
	if (!mctx)
		return;

	destroy_child_list(&mctx->child_list_head, mctx->childs_num);
	if(mctx->signal_event)
		event_free(mctx->signal_event);
	if(mctx->base)
		event_base_free(mctx->base);
	mitm_freeCA(mctx);
	free(mctx);
}

int mitm_loadCA(mitm_ctx* mctx, const char* cert_path, const char* cert_privkey_path)
{
	mctx->cacrt = get_cert(cert_path);
	mctx->cakey = rsa_get_key_fromfile(cert_privkey_path, 0, 0);
	mctx->leafkey = EVP_RSA_gen(DFLT_LEAFKEY_RSABITS);

	if (!mctx->cacrt || !mctx->cakey || !mctx->leafkey) {
		mitm_freeCA(mctx);
		return -1;
	}

	return 0;
}

void mitm_freeCA(mitm_ctx* mctx)
{
	if(mctx->cacrt)
		X509_free(mctx->cacrt);
	if(mctx->cakey)
		EVP_PKEY_free(mctx->cakey);
	if (mctx->leafkey)
		EVP_PKEY_free(mctx->leafkey);
	mctx->cacrt = NULL;
	mctx->cakey = NULL;
	mctx->leafkey = NULL;
}

void register_filter_cb_host(mitm_ctx* ctx, cbfilter_by_host cbfunc)
{
	ctx->cb_host = cbfunc;
}

void register_filter_cb_cared(mitm_ctx* ctx, cbfilter_by_http_header cbfunc)
{
	ctx->cb_cared = cbfunc;
}


void register_action_cb_http(mitm_ctx* ctx, cb_http_response on_response)
{
	ctx->cb_response = on_response;
}

void mitm_set_filter_mode(struct child* pchild)
{
	struct mitm_ctx_st* ctx = pchild->mctx;
	enum FILTER_RESULT res = DEFAULT_FILTER_RESULT;

	//is CONNECT?
	int is_https = 1;
	if (strcasecmp(pchild->req.method, "connect")) {
		is_https = 0;
	}	

	if (ctx->mode == WORK_MODE_FORWARD) {
		res = FILTER_RESULT_PASS;
	} else if (!is_https) {
		// only care https
		res = FILTER_RESULT_PASS;
	} else {
		//mode is WORK_MODE_MITM, and is CONNECT request
		if (ctx->cb_host)
			res = ctx->cb_host(pchild->req.host, pchild->mctx->arg);
	}

	pchild->filter_res = res;
}
