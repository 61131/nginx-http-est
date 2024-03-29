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

static char * ngx_http_est_command_pop(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_est_command_root_certificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void * ngx_http_est_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_est_match_attribute(ngx_http_est_loc_conf_t *lcf, ngx_str_t *str);

static char * ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_est_initialise(ngx_conf_t *cf);


ngx_http_est_dispatch_t ngx_http_est_dispatch[] = {

    /* 4.1.2 CA Certificates Request */

    { ngx_string("cacerts"),
        NGX_HTTP_GET,
        0,
        ngx_http_est_request_cacerts },

    /* 4.2.1 Simple Enrollment of Clients */

    { ngx_string("simpleenroll"),
        NGX_HTTP_POST,
        1,
        ngx_http_est_request_simple_request },

    /* 4.2.2 Simple Re-enrollment of Clients */

    { ngx_string("simplereenroll"),
        NGX_HTTP_POST,
        1,
        ngx_http_est_request_simple_request },

    /* 4.3.1 Full CMC Request */

    { ngx_string("fullcmc"),
        NGX_HTTP_POST,
        1,
        ngx_http_est_request_not_implemented },

    /* 4.4.1 Server-Side Key Generation Request */

    { ngx_string("serverkeygen"),
        NGX_HTTP_POST,
        1,
        ngx_http_est_request_simple_request },

    /* 4.5.1 CSR Attributes Request */

    { ngx_string("csrattrs"),
        NGX_HTTP_GET,
        0,
        ngx_http_est_request_csrattrs },

    { ngx_string(""), 0, 0, NULL }
};


static ngx_command_t ngx_http_est_commands[] = {

    /* Directives associated with EST operations */

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

    { ngx_string("est_pop"), 
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_est_command_pop,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, pop),
        NULL },

    { ngx_string("est_root_certificate"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_est_command_root_certificate,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, root_certificate),
        NULL },

    /* Directives associated with CA operations */

    { ngx_string("est_ca_private_key"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, ca_private_key),
        NULL },

    { ngx_string("est_ca_root_certificate"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, ca_root_certificate),
        NULL },

    { ngx_string("est_ca_serial_number"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, ca_serial_number),
        NULL },

    { ngx_string("est_ca_validity_days"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_est_loc_conf_t, ca_validity_days),
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


static char * 
ngx_http_est_command_csr_attrs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf = conf;
    BIO *in;
    BUF_MEM *buf;
    size_t length;
    char *pp, *rv;
    int ret;

    /* assert(lcf != NULL); */
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

    rv = NGX_CONF_OK;

error:
    BIO_free(in);
    BUF_MEM_free(buf);

    return rv;
}


static char * 
ngx_http_est_command_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf = conf;
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    /* assert(lcf != NULL); */
    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }
    if (lcf->enable) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = ngx_http_est_request;
    }
    return NGX_CONF_OK;
}


static char *
ngx_http_est_command_pop(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf = conf;
    ngx_str_t cp = ngx_string("challengePassword");
    ngx_str_t *attribute;
    char *rv;

    /* assert((obj = OBJ_nid2obj(NID_pkcs9_challengePassword)) != NULL); */
    /* assert(OBJ_obj2txt(buf, sizeof(buf), obj, 0) > 0); */

    /* assert(lcf != NULL); */
    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }
    if (lcf->pop) {

        /*
            When proof-of-possession is configured for the EST server, the object 
            identifier for the challengePassword is included within the list of 
            attributes mandated for certificate signing requests (CSR). Before this 
            object identifier is added to this list of attributes however, a check is 
            made to ensure that this object identifier is not already included.
        */

        rv = NGX_CONF_ERROR;
        /* assert(ngx_http_est_match_attribute(lcf, &attr) >= 0); */
        if (ngx_http_est_match_attribute(lcf, &cp) == 0) {
            attribute = ngx_array_push(lcf->attributes);
            if (attribute == NULL) {
                goto error;
            }
            attribute->len = cp.len + 1;
            attribute->data = ngx_pnalloc(cf->pool, attribute->len);
            if (attribute->data == NULL) {
                goto error;
            }
            (void) ngx_copy(attribute->data, cp.data, cp.len);
        }
    }

    rv = NGX_CONF_OK;
error:
    return rv;
}


static char * 
ngx_http_est_command_root_certificate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_est_loc_conf_t *lcf = conf;
    BIO *bp;
    char path[PATH_MAX], *rv;;

    /* assert(lcf != NULL); */
    rv = ngx_conf_set_str_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }
 
    /*
        The following code attempts to cache the root certificate specified in the 
        est_ca_root_certificate directive such that this can be more readily used 
        for certificate retrieval, enrollment and reenrollment requests.
    */

    bp = NULL;
    /* ngx_memzero(path, sizeof(path)); */
    ngx_snprintf((u_char *)path, sizeof(path),
            "%*s",
            lcf->root_certificate.len,
            lcf->root_certificate.data);
    path[lcf->root_certificate.len] = '\0';
    if (ngx_strlen(path) == 0) {
        goto error;
    }
    if (((bp = BIO_new_file(path, "r")) == NULL) ||
            ((lcf->ca_root = ngx_http_est_pkcs7(bp)) == NULL)) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "%s: error opening root certificate: \"%*s\"",
                MODULE_NAME,
                lcf->root_certificate.len,
                lcf->root_certificate.data);
        goto error;
    }
    rv = NGX_CONF_OK;

error:
    BIO_free(bp);
    return rv;
}


static void *
ngx_http_est_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_est_loc_conf_t *lcf;
    
    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_est_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }
    lcf->cf = cf;

    /*
        set by ngx_pcalloc():
            lcf->auth_request = { 0, NULL };
            lcf->ca_private_key = { 0, NULL };
            lcf->ca_root_certificate = { 0, NULL };
            lcf->ca_serial_number = { 0, NULL };
            lcf->csr_attrs = { 0, NULL };
            lcf->root_certificate = { 0, NULL };
    */

    lcf->attributes = NULL;
    lcf->ca_key = NGX_CONF_UNSET_PTR;
    lcf->ca_root = NGX_CONF_UNSET_PTR;
    lcf->ca_validity_days = NGX_CONF_UNSET;
    lcf->ca_x509 = NGX_CONF_UNSET_PTR;
    lcf->enable = NGX_CONF_UNSET;
    lcf->pop = NGX_CONF_UNSET;

    return lcf;
}


static ngx_int_t
ngx_http_est_match_attribute(ngx_http_est_loc_conf_t *lcf, ngx_str_t *str) {
    ngx_uint_t i;

    if (lcf->attributes == NULL) {
        if ((lcf->attributes = ngx_array_create(lcf->cf->pool, 8, sizeof(ngx_str_t))) == NULL) {
            return -1;
        }
    }
    for (i = 0; i < lcf->attributes->nelts; ++i) {
        if (ngx_strcmp(((ngx_str_t *) lcf->attributes->elts)[i].data, str->data) == 0) {
            return 1;
        }
    }
    return 0;
}


static char *
ngx_http_est_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_est_loc_conf_t *prev = parent;
    ngx_http_est_loc_conf_t *conf = child;
    
    ngx_conf_merge_ptr_value(conf->attributes, prev->attributes, NULL);
    ngx_conf_merge_str_value(conf->auth_request, prev->auth_request, "");
    ngx_conf_merge_ptr_value(conf->ca_key, prev->ca_key, NULL);
    ngx_conf_merge_str_value(conf->ca_private_key, prev->ca_private_key, "");
    ngx_conf_merge_ptr_value(conf->ca_root, prev->ca_root, NULL);
    ngx_conf_merge_str_value(conf->ca_root_certificate, prev->ca_root_certificate, "");
    ngx_conf_merge_str_value(conf->ca_serial_number, prev->ca_serial_number, "");
    ngx_conf_merge_value(conf->ca_validity_days, prev->ca_validity_days, 30);
    ngx_conf_merge_ptr_value(conf->ca_x509, prev->ca_x509, NULL);
    ngx_conf_merge_str_value(conf->csr_attrs, prev->csr_attrs, "");
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->pop, prev->pop, 0);
    ngx_conf_merge_str_value(conf->root_certificate, prev->root_certificate, "");
    
    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_http_est_initialise(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    /*
        The following installs this module as an access handler for HTTP requests. 
        This will be used to selectively perform HTTP authorization checks depending 
        upon the client verification configuration in place for a given location.
    */

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_est_auth;

    return NGX_OK;
}


