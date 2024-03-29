#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_est.h"


static ngx_int_t _ngx_http_est_auth_required(ngx_http_request_t *r);

static ngx_int_t _ngx_http_est_auth_response(ngx_http_request_t *r, void *data, ngx_int_t rc);


static ngx_int_t 
_ngx_http_est_auth_required(ngx_http_request_t *r) {
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_est_dispatch_t *d;
    ngx_http_est_loc_conf_t *lcf;
    ngx_str_t verify;
    ngx_int_t i, len;
    u_char *ptr, *uri;

    /*
        This function asserts where HTTP authentication is required in the context 
        of the nginx-http-est module. This authentication is not necessary where the 
        module is disabled, where the HTTP client has already been verified by way 
        of TLS certificate validation and where the specific EST end-point is 
        documented as being allowed without authentication.
    */

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    if (lcf->enable == 0) {
        return 0;
    }
    if ((r->connection->ssl) &&
            (ngx_ssl_get_client_verify(r->connection, r->pool, &verify) == NGX_OK) &&
            (ngx_strcmp(verify.data, "SUCCESS") == 0)) {
        return 0;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    /* assert(clcf != NULL); */
    /* assert(ngx_strstr(r->uri.data, clcf->name.data) == r->uri.data); */
    ptr = r->uri.data + ngx_strlen(clcf->name.data);
    if (*ptr == '/') {
        ++ptr;
    }
    len = r->uri.len - (ptr - r->uri.data);
    if (len <= 0) {
        return 0;
    }
    uri = ngx_pcalloc(r->pool, len + 1);
    if (uri == NULL) {
        return 0;
    }
    strncpy((char *)uri, (char *)ptr, len);

    for (i = 0;; ++i) {
        d = &ngx_http_est_dispatch[i];
        if (d->name.len == 0) {
            break;
        }
        if (ngx_strcmp(d->name.data, uri) != 0) {
            continue;
        }
        return (d->verify != 0);
    }

    return 0;
}


ngx_int_t
_ngx_http_est_auth_response(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    ngx_http_est_auth_request_t *ctx = data;

    ctx->done = 1;
    ctx->status = r->headers_out.status;
    return rc;
}


ngx_int_t 
ngx_http_est_auth(ngx_http_request_t *r) {
    ngx_http_est_loc_conf_t *lcf;
    ngx_http_est_auth_request_t *ctx;
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *ps;
    ngx_table_elt_t *h, *ho, **ph;

    if (!_ngx_http_est_auth_required(r)) {
        return NGX_OK;
    }
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    if (lcf->auth_request.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "%s: missing subrequest uri", 
                MODULE_NAME);
        /* return NGX_ERROR; */
        return NGX_HTTP_UNAUTHORIZED;   //  Authentication required, but subrequest URI configuration missing
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_est_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_est_auth_request_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ps = ngx_pcalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (ps == NULL) {
            return NGX_ERROR;
        }
        ps->handler = _ngx_http_est_auth_response;
        ps->data = ctx;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s: issuing subrequest for %*s",
                MODULE_NAME,
                lcf->auth_request.len,
                lcf->auth_request.data);
        if (ngx_http_subrequest(r, &lcf->auth_request, NULL, &sr, ps, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK) {
            return NGX_ERROR;
        }

        sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
        if (sr->request_body == NULL) {
            return NGX_ERROR;
        }
        sr->header_only = 1;
        ctx->request = sr;

        ngx_http_set_ctx(r, ctx, ngx_http_est_module);
        return NGX_AGAIN;
    }

    if (!ctx->done) {
        return NGX_AGAIN;
    }

    if (ctx->status == NGX_HTTP_FORBIDDEN) {
        return ctx->status;
    }

    if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
        sr = ctx->request;
        h = sr->headers_out.www_authenticate;
        if (!h && sr->upstream) {
            h = sr->upstream->headers_in.www_authenticate;
        }

        ph = &r->headers_out.www_authenticate;
        while (h) {
            ho = ngx_list_push(&r->headers_out.headers);
            if (ho == NULL) {
                return NGX_ERROR;
            }

            *ho = *h;
            ho->next = NULL;
            *ph = ho;
            ph = &ho->next;

            h = h->next;
        }
        return ctx->status;
    }
    if ((ctx->status >= NGX_HTTP_OK) &&
            (ctx->status < NGX_HTTP_SPECIAL_RESPONSE)) {
        return NGX_OK;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

