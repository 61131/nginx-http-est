#ifndef _NGX_HTTP_EST_H_INCLUDED_
#define _NGX_HTTP_EST_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/buffer.h>
#include <openssl/pkcs7.h>

typedef struct {

    ngx_flag_t  enable;

    ngx_str_t   csr_attrs;

    ngx_str_t   root_certificate;

    ngx_int_t   verify_client;

    PKCS7       *root;

    /*
        The following two members of this structure are used to store CSR attributes 
        information within ASN.1 Distinguished Encoding Rules (DER) format.
    */

    BUF_MEM     *buf;

    size_t      length;
}
ngx_http_est_loc_conf_t;

extern ngx_module_t ngx_http_est_module;

#endif  /* _NGX_HTTP_EST_H_INCLUDED_ */
