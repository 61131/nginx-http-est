#ifndef _NGX_HTTP_EST_H_INCLUDED_
#define _NGX_HTTP_EST_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>


#define MODULE_NAME     ("est")


typedef enum {
    HTTP_DISALLOW = 0,
    HTTP_ALLOW = 1,
    HTTP_LIMIT = 2,
}
ngx_http_est_http_e;

typedef enum {
    VERIFY_NONE = 0,
    VERIFY_AUTHENTICATION = 1,
    VERIFY_CERTIFICATE = 2,
    VERIFY_BOTH = 3,
}
ngx_http_est_verify_e;

typedef struct {
    ngx_conf_t  *cf;

    ngx_str_t   auth_request;
    ngx_str_t   ca_private_key;
    ngx_str_t   ca_root_certificate;
    ngx_str_t   ca_serial_number;
    ngx_int_t   ca_validity_days;
    ngx_str_t   csr_attrs;
    ngx_flag_t  enable;
    ngx_int_t   http; 
    ngx_flag_t  legacy;
    ngx_flag_t  pop;
    ngx_int_t   verify_client;

    ngx_array_t *attributes;

    /*
        The following members of this data structure are pointers to the certificate 
        authority (CA) X.509 certificate and associated private key which are used 
        for signing issued certificates. 
    */

    X509        *ca_x509;   //  Unused optimisation
	EVP_PKEY    *ca_key;    //  Unused optimisation
    PKCS7       *ca_root;
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

PKCS7 * ngx_http_est_pkcs7(BIO *bp);

EVP_PKEY * ngx_http_est_privkey(ngx_http_request_t *r, X509_REQ *req);

ngx_int_t ngx_http_est_request(ngx_http_request_t *r);

ngx_int_t ngx_http_est_request_cacerts(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_est_request_csrattrs(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_est_request_not_implemented(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_est_request_simple_request(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_est_tls_unique(ngx_http_request_t *r, ngx_str_t *s);

X509 * ngx_http_est_x509_generate(ngx_http_request_t *r, X509_REQ *req);

ngx_int_t ngx_http_est_x509_verify(X509_REQ *req);


#endif  /* _NGX_HTTP_EST_H_INCLUDED_ */
