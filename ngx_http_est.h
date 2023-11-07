#ifndef _NGX_HTTP_EST_H_INCLUDED_
#define _NGX_HTTP_EST_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/pkcs7.h>

typedef struct {

    ngx_flag_t  enable;

    ngx_int_t   verify_client;

    ngx_str_t   root_certificate;

    PKCS7       *root;
}
ngx_http_est_loc_conf_t;

extern ngx_module_t ngx_http_est_module;

#endif  /* _NGX_HTTP_EST_H_INCLUDED_ */
