#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_module.h>

#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "ngx_http_est.h"


enum {
    VERIFY_NONE = 0,
    VERIFY_AUTHENTICATION = 1,
    VERIFY_CERTIFICATE = 2,
    VERIFY_BOTH = 3,
};

static void * ngx_http_est_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_est_directive_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_est_directive_root_certificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_est_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_est_handler_cacerts(ngx_http_request_t *r, ngx_buf_t *b);

static ngx_int_t ngx_http_est_initialise(ngx_conf_t *cf);

static char * ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


typedef struct {

    ngx_str_t name;

    ngx_uint_t method;

    ngx_flag_t verify;

    ngx_int_t (*handler)(ngx_http_request_t *r, ngx_buf_t *b);
}
ngx_http_est_dispatch_t;

static ngx_http_est_dispatch_t ngx_http_est_dispatch[] = {

    /*
        4.1.2. CA Certificates Request

        EST clients request the EST CA TA database information of the CA (in the 
        form of certificates) with an HTTPS GET message using an operation path of 
        "/cacerts". 
    */

    { ngx_string("cacerts"),
        NGX_HTTP_GET,
        0,
        ngx_http_est_handler_cacerts },

    /*
        4.2. Client Certificate Request Functions

        EST clients request a certificate from the EST server with an HTTPS POST 
        using the operation path value of "/simpleenroll".  EST clients request a 
        renew/rekey of existing certificates with an HTTP POST using the operation 
        path value of "/simplereenroll". EST servers MUST support the /simpleenroll 
        and /simplereenroll functions.
    */

    { ngx_string("simpleenroll"),
        NGX_HTTP_GET|NGX_HTTP_POST, /* NGX_HTTP_POST */
        1,
        NULL },

    { ngx_string(""), 0, 0, NULL }
};


static ngx_conf_enum_t ngx_http_est_client_verify[] = {
    { ngx_string("none"), VERIFY_NONE },
    { ngx_string("auth"), VERIFY_AUTHENTICATION },
    { ngx_string("cert"), VERIFY_CERTIFICATE },
    { ngx_string("both"), VERIFY_BOTH },
    { ngx_null_string, 0 },
};

static ngx_command_t ngx_http_est_commands[] = {
    { ngx_string("est"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_http_est_directive_enable,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, enable),
        NULL },
        
    { ngx_string("est_verify_client"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, verify_client),
        &ngx_http_est_client_verify },

    { ngx_string("est_root_certificate"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_est_directive_root_certificate,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, root_certificate),
        NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_est_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_est_initialise,            /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_est_create_loc_conf,       /* create location configuration */
    ngx_http_est_merge_loc_conf         /* merge location configuration */
};

ngx_module_t ngx_http_est_module = {
    NGX_MODULE_V1,
    &ngx_http_est_module_ctx,           /* module context */
    ngx_http_est_commands,              /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_est_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_est_loc_conf_t *elcf;
    
    elcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_est_loc_conf_t));
    if (elcf == NULL) {
        return NULL;
    }

    /*
        set by ngx_pcalloc():
            elcf->root_certificate = { 0, NULL };
            elcf->root = NULL;
    */

    elcf->enable = NGX_CONF_UNSET;
    elcf->verify_client = NGX_CONF_UNSET;

    return elcf;
}


static char * 
ngx_http_est_directive_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_ssl_srv_conf_t *sscf;
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (sscf->verify != /* optional */ 2) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "ssl_verify_client must be set to \"optional\" for est operations");
        return NGX_CONF_ERROR;
    }
 
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_est_handler;
    return NGX_CONF_OK;
}


static char * 
ngx_http_est_directive_root_certificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf;
    BIO *bp;
    PKCS7 *p7;
    PKCS7_SIGNED *p7s;
    STACK_OF(X509) *stack;
    STACK_OF(X509_INFO) *sk;
    X509_INFO *info;
    ngx_uint_t c;
    char *rv;

    rv = ngx_conf_set_str_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_CONF_ERROR;
    }
 
    /*
        The following code attempts to cache the root certificate specified in the 
        est_root_certificate directive such that this can be more readily used for 
        certificate retrieval, enrollment and reenrollment requests.
    */

    p7 = NULL;
    bp = NULL;
    stack = NULL;
    sk = NULL;

    rv = NGX_CONF_ERROR;

    if ((p7 = PKCS7_new()) == NULL) {
        goto error;
    }
    if ((p7s = PKCS7_SIGNED_new()) == NULL) {
        goto error;
    }
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    p7->d.sign = p7s;
    p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);
    if (!ASN1_INTEGER_set(p7s->version, 1)) {
        goto error;
    }

    if ((stack = sk_X509_new_null()) == NULL) {
        goto error;
    }
    p7s->cert = stack;
    if ((bp = BIO_new_file((const char *)lcf->root_certificate.data, "r")) == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "error opening root certificate: \"%*s\"",
                lcf->root_certificate.len,
                lcf->root_certificate.data);
        goto error;
    }
    if ((sk = PEM_X509_INFO_read_bio(bp, NULL, NULL, NULL)) == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "error reading root certificate: \"%*s\"",
                lcf->root_certificate.len,
                lcf->root_certificate.data);
        goto error;
    }

    c = 0;
    while (sk_X509_INFO_num(sk)) {
        info = sk_X509_INFO_shift(sk);
        if (info->x509 != NULL) {
            sk_X509_push(p7s->cert, info->x509);
            info->x509 = NULL;
            ++c;
        }
        X509_INFO_free(info);
    }
    /* assert(c > 0); */

    lcf->root = p7;
    rv = NGX_CONF_OK;

error:
    sk_X509_INFO_free(sk);
    BIO_free(bp);

    if (rv != NGX_CONF_OK) {
    	PKCS7_free(p7);
    }
    return rv;
}


static ngx_int_t
ngx_http_est_handler(ngx_http_request_t *r) {
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_est_dispatch_t *d;
    ngx_http_est_loc_conf_t *lcf;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_int_t c, i, rc;
    ngx_str_t verify;
    u_char *ptr, *uri;

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

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_DECLINED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_DECLINED;
    }
    ptr = r->uri.data;
    if (ngx_strstr(ptr, clcf->name.data) != (char *)ptr) {
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
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "est: \"%*s\"", (size_t)c, ptr);

    /*
        Determine whether the requested EST API end-point is supported for the given 
        HTTP method and SSL client verification state.
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
            if ((lcf->verify_client & VERIFY_AUTHENTICATION) != 0) {
                return NGX_HTTP_FORBIDDEN;
            }
            if ((lcf->verify_client & VERIFY_CERTIFICATE) != 0) {
                if (ngx_ssl_get_client_verify(r->connection, r->pool, &verify) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (ngx_strcmp(verify.data, "SUCCESS") != 0) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "failed certificate verification");
                    return NGX_HTTP_FORBIDDEN;
                }
            }
        }

        break;  //  rc == 0
    }
    if (rc != 0) {
        return NGX_HTTP_NOT_FOUND;
    }
    
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

    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if ((r->header_only) ||
            (rc == NGX_ERROR) ||
            (rc > NGX_OK)) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t 
ngx_http_est_handler_cacerts(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_http_est_loc_conf_t *lcf;
    ngx_table_elt_t *h;
    BIO *bp;
    u_char *content;
    char *data;
    int c, rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_DECLINED;
    }
    ngx_http_discard_request_body(r);

    /*
        Populate the response headers and body for /cacerts request - Note that this 
        implementation may be modified such that more of the header content is 
        generated within the ngx_http_est_handler function.
    */

    r->headers_out.content_type_len = sizeof("application/pkcs7-mime") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/pkcs7-mime");
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&h->key, "Content-Type-Encoding");
    ngx_str_set(&h->value, "base64");
    h->hash = 1;

    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if ((bp = BIO_new(BIO_s_mem())) == NULL) {
        return rc;
    }

    for (;;) {
        if (!PEM_write_bio_PKCS7(bp, lcf->root)) {
            break;
        }
        if ((c = BIO_get_mem_data(bp, &data)) <= 0) {
            break;
        }

        if ((content = ngx_pcalloc(r->pool, c)) == NULL) {
            break;
        }
        b->pos = b->last = content;
        b->memory = 1;
        b->last = ngx_copy(b->last, data, c);

        rc = NGX_OK;
        break;
    }

    BIO_free(bp);
    return rc;
}


static ngx_int_t 
ngx_http_est_initialise(ngx_conf_t *cf) {
//  Add checks to ensure all configuration requirements fulfilled

    return NGX_OK;
}

static char *
ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_est_loc_conf_t *prev = parent;
    ngx_http_est_loc_conf_t *conf = child;
    
    if (conf->enable == NGX_CONF_UNSET) {
        conf->enable = (prev->enable != NGX_CONF_UNSET) ? prev->enable : 0;
    }
    ngx_conf_merge_value(conf->verify_client, prev->verify_client, VERIFY_CERTIFICATE);
    
    if (conf->root == NULL) {
        conf->root = (prev->root != NULL) ? prev->root : NULL;
    }

    return NGX_CONF_OK;
}


