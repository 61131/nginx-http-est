#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_module.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "ngx_http_est.h"


static char * ngx_http_est_command_csr_attrs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_est_command_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_est_command_root_certificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void * ngx_http_est_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_est_initialise(ngx_conf_t *cf);


ngx_http_est_dispatch_t ngx_http_est_dispatch[] = {

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
        NGX_HTTP_POST,
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
        offsetof(ngx_http_est_loc_conf_t, auth_request),
        NULL },

    { ngx_string("est_csr_attrs"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_est_command_csr_attrs,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, csr_attrs),
        NULL },

    { ngx_string("est_permit_http"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, permit_http),
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


static char * 
ngx_http_est_command_csr_attrs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf = conf;
    BIO *in;
    BUF_MEM *buf;
    size_t length;
    char *pp, *rv;
    int ret;

    rv = ngx_conf_set_str_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /*
        The following code attempts to parse and cache the ASN.1 sequence specified 
        in the est_csr_attrs directive. This information will be used for both the 
        validation of attributes in CSRs received from clients and when responding 
        to requests for a list of such attributes ("/csrattrs"). As such, this 
        information is cached in both as a buffer of Distinguished Encoding Rules 
        (DER) bytes as read from the file and returned to CSR attributes operations
        ("/csrattrs") and as an array of parsed attributes for validating 
        certificate requests.
    */

    rv = NGX_CONF_ERROR;

    in = NULL;
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
        if (lcf->attributes == NULL) {
            lcf->attributes = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t));
            if (lcf->attributes == NULL) {
                goto error;
            }
        }
        pp = buf->data;
        if (ngx_http_est_asn1_parse(lcf->attributes, (const unsigned char **) &pp, length, 0) != 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, 
                    "%s: error reading certificate attributes: \"%*s\"",
                    MODULE_NAME,
                    lcf->csr_attrs.len,
                    lcf->csr_attrs.data);
            goto error;
        }
    }

    buf->length = length;
    lcf->buf = buf;
    rv = NGX_CONF_OK;

error:
    BIO_free(in);
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

    /*
        This validation check might have to move to after all configuration has been 
        read and be executed only where the est_verify_client directive includes 
        verification by certificate (cert or both).
    */

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


static void *
ngx_http_est_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_est_loc_conf_t *lcf;
    
    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_est_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    /*
        set by ngx_pcalloc():
            lcf->auth_request = { 0, NULL };
            lcf->csr_attrs = { 0, NULL };
            lcf->root_certificate = { 0, NULL };
    */

    lcf->enable = NGX_CONF_UNSET;
    lcf->permit_http = NGX_CONF_UNSET;
    lcf->verify_client = NGX_CONF_UNSET;
    lcf->attributes = NULL;
    lcf->buf = NGX_CONF_UNSET_PTR;
    lcf->root = NGX_CONF_UNSET_PTR;

    return lcf;
}


static char *
ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_est_loc_conf_t *prev = parent;
    ngx_http_est_loc_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->auth_request, prev->auth_request, "");
    ngx_conf_merge_str_value(conf->csr_attrs, prev->csr_attrs, "");
    ngx_conf_merge_value(conf->permit_http, prev->permit_http, 0);
    ngx_conf_merge_str_value(conf->root_certificate, prev->root_certificate, "");
    ngx_conf_merge_value(conf->verify_client, prev->verify_client, VERIFY_CERTIFICATE);
    ngx_conf_merge_ptr_value(conf->attributes, prev->attributes, NULL);
    ngx_conf_merge_ptr_value(conf->buf, prev->buf, NULL);
    ngx_conf_merge_ptr_value(conf->root, prev->root, NULL);
    
    return NGX_CONF_OK;
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


