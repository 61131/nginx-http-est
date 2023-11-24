#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#include "ngx_http_est.h"


static void _ngx_http_est_request_simpleenroll(ngx_http_request_t *r);


static void
_ngx_http_est_request_simpleenroll(ngx_http_request_t *r) {
    ngx_int_t rc;

    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (r->request_body == NULL) {
        goto error;
    }

    rc = NGX_HTTP_NO_CONTENT;
error:
    ngx_http_finalize_request(r, rc);
}


ngx_int_t
ngx_http_est_request(ngx_http_request_t *r) {
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_est_dispatch_t *d;
    ngx_http_est_loc_conf_t *lcf;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_int_t c, i, rc;
    ngx_str_t verify;
    u_char *ptr, *uri;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_DECLINED;
    }
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_DECLINED;
    }


    /*
        This function implements handling for HTTP requests submitted to the EST API 
        end-point. This is performed by first stripping the leading portion of the 
        URI as specified within the location configuration block - This allows the
        EST module to seamlessly handle different - and even non-standard - path
        segments that may be employed within a configuration.
    */

    if (!r->connection->ssl) {  //  Move to allow /cacerts over HTTP?
        return NGX_HTTP_FORBIDDEN;
    }

    ptr = r->uri.data;
    if (ngx_strstr(ptr, clcf->name.data) != (char *) ptr) {
        return NGX_DECLINED;
    }
    ptr += ngx_strlen(clcf->name.data);
    if (*ptr == '/') {
        ++ptr;
    }
    c = r->uri.len - (ptr - r->uri.data);
    if (c <= 0) {
        return NGX_DECLINED;
    }
    uri = ngx_pcalloc(r->pool, c + 1);  //  NB: + 1
    if (uri == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    strncpy((char *)uri, (char *)ptr, c);
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s: \"%*s\"", 
            MODULE_NAME,
            (size_t)c, 
            ptr);


    /*
        Determine whether the requested EST API end-point is supported for the given 
        HTTP method and SSL client verification state. Note that HTTP-based 
        authorization, if configured and required for an operation end-point, is 
        verified in the access phase handler (ngx_http_est_auth).
    */

    for (i = 0, rc = -1;; ++i) {
        d = &ngx_http_est_dispatch[i];
        if (d->name.len == 0) {
            break;
        }
        if ((rc = ngx_strcmp(d->name.data, uri)) != 0) {
            continue;
        }
        if ((d->method & r->method) == 0) {
            return NGX_HTTP_NOT_ALLOWED;
        }
        if (d->verify) {
            if ((lcf->verify_client & VERIFY_CERTIFICATE) != 0) {
                if (ngx_ssl_get_client_verify(r->connection, r->pool, &verify) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (ngx_strcmp(verify.data, "SUCCESS") != 0) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                            "%s: failed certificate verification",
                            MODULE_NAME);
                    return NGX_HTTP_FORBIDDEN;
                }
            }
        }

        break;  //  rc == 0
    }
    if (rc != 0) {
        return NGX_HTTP_NOT_FOUND;
    }
    
    if (r->method != NGX_HTTP_POST) {
        ngx_http_discard_request_body(r);
    }
    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.status = NGX_HTTP_OK;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out.buf = b;
    out.next = NULL;

    /* assert(d != NULL); */
    /* assert(d->handler != NULL); */
    if (d->handler == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if ((rc = d->handler(r, b)) != NGX_OK) {
        return rc;
    }
    b->last_buf = (r == r->main) ? 1 :0;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if ((r->header_only) ||
            (rc == NGX_ERROR) ||
            (rc > NGX_OK)) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


ngx_int_t 
ngx_http_est_request_cacerts(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_http_est_loc_conf_t *lcf;
    ngx_table_elt_t *h;
    BIO *bp;
    BUF_MEM *ptr;
    u_char *content;
    int rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_DECLINED;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/pkcs7-mime") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/pkcs7-mime");
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&h->key, "Content-Type-Encoding");
    ngx_str_set(&h->value, "base64");
    h->hash = 1;

    rc = NGX_ERROR;
    if (((bp = BIO_new(BIO_s_mem())) == NULL) ||
            (!PEM_write_bio_PKCS7(bp, lcf->root))) {
        goto error;
    }

    BIO_get_mem_ptr(bp, &ptr);
    /* assert(ptr != NULL); */
    if ((content = ngx_pcalloc(r->pool, ptr->length)) == NULL) {
        goto error;
    }
    b->pos = b->last = content;
    b->memory = 1;
    b->last = ngx_copy(b->last, ptr->data, ptr->length);

    rc = NGX_OK;

error:
    BIO_free(bp);
    return rc;
}


ngx_int_t 
ngx_http_est_request_csrattrs(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_http_est_loc_conf_t *lcf;
    ngx_str_t data, encoded;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_DECLINED;
    }

    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_type_len = sizeof("application/csrattrs") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/csrattrs");

    if (lcf->length > 0) {
        data.len = lcf->length;
        data.data = (u_char *)lcf->buf->data;
        encoded.len = ngx_base64_encoded_length(data.len);
        encoded.data = ngx_pcalloc(r->pool, encoded.len + 2);
        if (encoded.data == NULL) {
            return NGX_ERROR;
        }
        ngx_encode_base64(&encoded, &data);
        b->pos = b->last = encoded.data;
        b->memory = 1;
        b->last += encoded.len;
        b->last = ngx_copy(b->last, CRLF, 2);

        r->headers_out.status = NGX_HTTP_OK;
    }

    return NGX_OK;
}


ngx_int_t 
ngx_http_est_request_simpleenroll(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_int_t rc;

    /*
        This function will process the request headers before establishing a 
        callback handler to processing the request body which is expected to 
        contain the certificate signing request (CSR) associated with the 
        /simpleenroll request.
    */

    /* assert(r->method == NGX_HTTP_POST); */
    rc = ngx_http_read_client_request_body(r, _ngx_http_est_request_simpleenroll);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_OK;
}


