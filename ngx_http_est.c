#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_module.h>

#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "ngx_http_est.h"
#include "ngx_http_est_base64.h"


#define MODULE_NAME     ("est")


enum {
    VERIFY_NONE = 0,
    VERIFY_AUTHENTICATION = 1,
    VERIFY_CERTIFICATE = 2,
    VERIFY_BOTH = 3,
};


static ngx_int_t ngx_http_est_auth(ngx_http_request_t *r);

static char * ngx_http_est_command_csr_attrs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_est_command_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_est_command_root_certificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_est_content_simpleenroll(ngx_http_request_t *r);

static void * ngx_http_est_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_est_initialise(ngx_conf_t *cf);

static char * ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_est_request(ngx_http_request_t *r);

static ngx_int_t ngx_http_est_request_cacerts(ngx_http_request_t *r, ngx_buf_t *b);

static ngx_int_t ngx_http_est_request_csrattrs(ngx_http_request_t *r, ngx_buf_t *b);

static ngx_int_t ngx_http_est_request_simpleenroll(ngx_http_request_t *r, ngx_buf_t *b);



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
        ngx_http_est_request_cacerts },

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
        ngx_http_est_request_simpleenroll },

    /*
        4.5.1. CSR Attributes Request

        The EST client requests a list of CA-desired CSR attributes from the CA by
        sending an HTTPS GET message to the EST server with an operations path of
        "/csrattrs".
    */

    { ngx_string("csrattrs"),
        NGX_HTTP_GET,
        0,
        ngx_http_est_request_csrattrs },

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
        ngx_http_est_command_enable,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, enable),
        NULL },
        
    { ngx_string("est_auth_request"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, uri),
        NULL },

    { ngx_string("est_csr_attrs"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_est_command_csr_attrs,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, csr_attrs),
        NULL },

    { ngx_string("est_root_certificate"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_est_command_root_certificate,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, root_certificate),
        NULL },

    { ngx_string("est_verify_client"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, verify_client),
        &ngx_http_est_client_verify },

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


static ngx_int_t 
ngx_http_est_auth(ngx_http_request_t *r) {
    ngx_http_est_loc_conf_t *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if ((lcf->verify_client & VERIFY_AUTHENTICATION) == 0) {
        return NGX_DECLINED;
    }
    if (lcf->uri.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "%s: missing subrequest uri", 
                MODULE_NAME);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char * 
ngx_http_est_command_csr_attrs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf = conf;
    BIO *in, *out;
    BUF_MEM *buf;
    size_t length;
    char *rv;
    int ret;

    rv = ngx_conf_set_str_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /*
        The following code attempts to parse and cache the ASN.1 sequence specified 
        in the est_csr_attrs directive. This information will be used for both the 
        validation of attributes in CSRs received from clients and when responding 
        to requests for a list of such attributes ("/csrattrs").

        NB: Only DER encoded CSR attributes file is supported at this stage
    */

    rv = NGX_CONF_ERROR;

    in = out = NULL;
    buf = NULL;

    if ((in = BIO_new_file((char *) lcf->csr_attrs.data, "rb")) == NULL) {
        goto error;
    }
    if ((buf = BUF_MEM_new()) == NULL) {
        goto error;
    }
    for (length = 0;;) {
        if (!BUF_MEM_grow(buf, BUFSIZ + length)) {
            goto error;
        }
        ret = BIO_read(in, &(buf->data[length]), BUFSIZ);
        if (ret <= 0) {
            break;
        }
        length += ret;
    }
    if (length > 0) {
        if ((out = BIO_new(BIO_s_mem())) == NULL) {
            goto error;
        }
        //  Need to do something with the ASN.1 sequence
        if (!ASN1_parse(out, (const unsigned char *) buf->data, length, 0)) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, 
                    "%s: error reading CSR attributes: \"%*s\"",
                    MODULE_NAME,
                    lcf->csr_attrs.len,
                    lcf->csr_attrs.data);
            goto error;
        }
    }

    lcf->buf = buf;
    lcf->length = length;
    rv = NGX_CONF_OK;

error:
    BIO_free(in);
    BIO_free(out);

    if (rv != NGX_CONF_OK) {
        BUF_MEM_free(buf);
    }
    return rv;
}


static char * 
ngx_http_est_command_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
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
                "%s: ssl_verify_client must be set to \"optional\"",
                MODULE_NAME);
        return NGX_CONF_ERROR;
    }
 
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_est_request;
    return NGX_CONF_OK;
}


static char * 
ngx_http_est_command_root_certificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf = conf;
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
                "%s: error opening root certificate: \"%*s\"",
                MODULE_NAME,
                lcf->root_certificate.len,
                lcf->root_certificate.data);
        goto error;
    }
    if ((sk = PEM_X509_INFO_read_bio(bp, NULL, NULL, NULL)) == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "%s: error reading root certificate: \"%*s\"",
                MODULE_NAME,
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


static void
ngx_http_est_content_simpleenroll(ngx_http_request_t *r) {
    ngx_int_t rc;

    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (r->request_body == NULL) {
        goto error;
    }

error:
    ngx_http_finalize_request(r, rc);
}


static void *
ngx_http_est_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_est_loc_conf_t *lcf;
    
    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_est_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    /*
        set by ngx_pcalloc():
            lcf->csr_attrs = { 0, NULL };
            lcf->root_certificate = { 0, NULL };
            lcf->uri = { 0, NULL };
    */

    lcf->buf = NGX_CONF_UNSET_PTR;
    lcf->enable = NGX_CONF_UNSET;
    lcf->length = NGX_CONF_UNSET_SIZE;
    lcf->root = NGX_CONF_UNSET_PTR;
    lcf->verify_client = NGX_CONF_UNSET;

    return lcf;
}


static ngx_int_t 
ngx_http_est_initialise(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    /*
        TODO: Add checks to ensure that all configuration requirements for EST 
        operations have been fulfiled.
    */

    /*
        The following installs this module as an access handler for HTTP requests. 
        This will be used to selectively perform authorization checks depending upon 
        the client verification configuration in place for a given location.
    */

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_est_auth;

    return NGX_OK;
}

static char *
ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_est_loc_conf_t *prev = parent;
    ngx_http_est_loc_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->verify_client, prev->verify_client, VERIFY_CERTIFICATE);
    ngx_conf_merge_ptr_value(conf->root, prev->root, NULL);
    ngx_conf_merge_ptr_value(conf->buf, prev->buf, NULL);
    ngx_conf_merge_size_value(conf->length, prev->length, 0);
    
    return NGX_CONF_OK;
}


static ngx_int_t
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
                //  NB: Add subrequest processing for authentication
                return NGX_HTTP_FORBIDDEN;
            }
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


static ngx_int_t 
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


static ngx_int_t 
ngx_http_est_request_csrattrs(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_http_est_loc_conf_t *lcf;
    ngx_table_elt_t *h;
    u_char *content;
    size_t length;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_DECLINED;
    }

    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_type_len = sizeof("application/csrattrs") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/csrattrs");
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&h->key, "Content-Type-Encoding");
    ngx_str_set(&h->value, "base64");
    h->hash = 1;

    if (lcf->length > 0) {
        length = lcf->length;
        content = ngx_http_est_base64_encode(r, lcf->buf->data, &length);
        b->pos = b->last = content;
        b->memory = 1;
        b->last += length;

        r->headers_out.status = NGX_HTTP_OK;
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_est_request_simpleenroll(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_int_t rc;

    /*
        This function will process the request headers before establishing a 
        callback handler to processing the request body which is expected to 
        contain the certificate signing request (CSR) associated with the 
        /simpleenroll request.
    */

    /* assert(r->method == NGX_HTTP_POST); */
    rc = ngx_http_read_client_request_body(r, ngx_http_est_content_simpleenroll);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_OK;
}



