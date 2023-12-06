#ifndef _NGX_HTTP_EST_H_INCLUDED_
#define _NGX_HTTP_EST_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/buffer.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>


#define MODULE_NAME     ("est")


typedef enum {
    VERIFY_NONE = 0,
    VERIFY_AUTHENTICATION = 1,
    VERIFY_CERTIFICATE = 2,
    VERIFY_BOTH = 3,
}
ngx_http_est_verify_e;

typedef struct {
    ngx_str_t   auth_request;
    ngx_str_t   ca_private_key;
    ngx_str_t   ca_root_certificate;
    ngx_str_t   ca_serial_number;
    ngx_int_t   ca_validity_days;
    ngx_str_t   csr_attrs;
    ngx_flag_t  enable;
    ngx_flag_t  permit_http;
    ngx_int_t   verify_client;

    /* array(ngx_str_t) CSR attributes */
    ngx_array_t *attributes;
    /* BUF_MEM CSR attributes, DER encoded */
    BUF_MEM     *buf;
    /* PKCS7 root certificate */
    PKCS7       *root;

    /*
        The following members of this data structure are pointers to the certificate 
        authority (CA) X.509 certificate and associated private key which are used 
        for signing issued certificates.
    */

    X509        *x509;
    EVP_PKEY    *pkey;
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


ngx_int_t ngx_http_est_asn1_parse(ngx_array_t *array, const unsigned char **data, size_t length, off_t offset);

ngx_int_t ngx_http_est_auth(ngx_http_request_t *r);

ngx_int_t ngx_http_est_auth_required(ngx_http_request_t *r);

ngx_int_t ngx_http_est_auth_response(ngx_http_request_t *r, void *data, ngx_int_t rc);

ngx_int_t ngx_http_est_request(ngx_http_request_t *r);

ngx_int_t ngx_http_est_request_cacerts(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_est_request_csrattrs(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_est_request_not_implemented(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_est_request_simple_request(ngx_http_request_t *r, ngx_buf_t *b);

X509 * ngx_http_est_x509_generate(ngx_http_request_t *r, X509_REQ *req);

ngx_int_t ngx_http_est_x509_verify(X509_REQ *req);


#endif  /* _NGX_HTTP_EST_H_INCLUDED_ */
