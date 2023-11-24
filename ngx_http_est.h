#ifndef _NGX_HTTP_EST_H_INCLUDED_
#define _NGX_HTTP_EST_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/buffer.h>
#include <openssl/pkcs7.h>


#define MODULE_NAME     ("est")


typedef enum {
    VERIFY_NONE = 0,
    VERIFY_AUTHENTICATION = 1,
    VERIFY_CERTIFICATE = 2,
    VERIFY_BOTH = 3,
}
ngx_http_est_verify_e;

typedef struct {
    ngx_flag_t  enable;
    ngx_str_t   csr_attrs;
    ngx_str_t   root_certificate;
    ngx_int_t   verify_client;
    ngx_str_t   uri;

    PKCS7       *root;
    BUF_MEM     *buf;

    size_t      length;
}
ngx_http_est_loc_conf_t;

typedef struct {
    ngx_uint_t done;
    ngx_uint_t status;
    ngx_http_request_t *request;
}
ngx_http_est_auth_request_t;

typedef struct {
    ngx_str_t name;
    ngx_uint_t method;
    ngx_flag_t verify;
    ngx_int_t (*handler)(ngx_http_request_t *r, ngx_buf_t *b);
}
ngx_http_est_dispatch_t;


extern ngx_http_est_dispatch_t ngx_http_est_dispatch[];
extern ngx_module_t ngx_http_est_module;


ngx_int_t ngx_http_est_auth(ngx_http_request_t *r);
ngx_int_t ngx_http_est_auth_required(ngx_http_request_t *r);
ngx_int_t ngx_http_est_auth_response(ngx_http_request_t *r, void *data, ngx_int_t rc);
ngx_int_t ngx_http_est_request(ngx_http_request_t *r);
ngx_int_t ngx_http_est_request_cacerts(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_est_request_csrattrs(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_est_request_simpleenroll(ngx_http_request_t *r, ngx_buf_t *b);


#endif  /* _NGX_HTTP_EST_H_INCLUDED_ */
