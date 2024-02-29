#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <limits.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "ngx_http_est.h"


#define _X509_SERIAL_NUMBER_EXTENSION   ".srl"


static X509 * _ngx_http_est_x509_cacert(ngx_http_request_t *r);

static EVP_PKEY * _ngx_http_est_x509_privkey(ngx_http_request_t *r);

static BIGNUM * _ngx_http_est_x509_serial_load(const char *path);

static ASN1_INTEGER * _ngx_http_est_x509_serial_number(ngx_http_request_t *r);

static ngx_int_t _ngx_http_est_x509_serial_save(const char *path, const BIGNUM *value, ASN1_INTEGER **asn_value);


static X509 *
_ngx_http_est_x509_cacert(ngx_http_request_t *r) {
    ngx_http_est_loc_conf_t *lcf;
    BIO *in;
    X509 *cert;
    char path[PATH_MAX];

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    ngx_memzero(path, sizeof(path));
    ngx_snprintf((u_char *)path, sizeof(path), 
            "%*s", 
            lcf->ca_root_certificate.len,
            lcf->ca_root_certificate.data);
    if (ngx_strlen(path) == 0) {
        return NULL;
    }
    if ((in = BIO_new_file((const char *)path, "r")) == NULL) {
        return NULL;
    }
    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
    BIO_free(in);
    return cert;
}


static EVP_PKEY *
_ngx_http_est_x509_privkey(ngx_http_request_t *r) {
    ngx_http_est_loc_conf_t *lcf;
    BIO *in;
    EVP_PKEY *pkey;
    char path[PATH_MAX];

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    ngx_memzero(path, sizeof(path));
    ngx_snprintf((u_char *)path, sizeof(path),
            "%*s",
            lcf->ca_private_key.len,
            lcf->ca_private_key.data);
    if (ngx_strlen(path) == 0) {
        return NULL;
    }
    if ((in = BIO_new_file((const char *)path, "r")) == NULL) {
        return NULL;
    }
    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    return pkey;
}


static BIGNUM *
_ngx_http_est_x509_serial_load(const char *path) {
    ASN1_INTEGER *val;
    BIGNUM *ret;
    BIO *in;
    char buf[LINE_MAX];

    ret = NULL;

    in = BIO_new_file(path, "r");
    if (in == NULL) {
        ret = BN_new();
        if (ret != NULL) {

            /*
                IETF RFC 5280 states that the certificate serial numbed must be less than or 
                equal to 20 bytes in length. The following generates 159-bit length random 
                value, which may be prepended by a bit value of zero, in line with DER 
                encoding rules, to generate a maximum length serial number.
            */

            BN_rand(ret, 159, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        }
    }
    else {
        val = ASN1_INTEGER_new();
        if (val != NULL) {
            if (a2i_ASN1_INTEGER(in, val, buf, sizeof(buf))) {
                ret = ASN1_INTEGER_to_BN(val, NULL);
            }
            ASN1_INTEGER_free(val);
        }
    }
    BIO_free(in);
    return ret;
}


static ASN1_INTEGER * 
_ngx_http_est_x509_serial_number(ngx_http_request_t *r) {
    ngx_http_est_loc_conf_t *lcf;
    ASN1_INTEGER *val;
    BIGNUM *num;
    char path[PATH_MAX], *ptr;
    size_t length;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    ngx_memzero(path, sizeof(path));
    ngx_snprintf((u_char *)path, sizeof(path), 
            "%*s", 
            lcf->ca_serial_number.len, 
            lcf->ca_serial_number.data);
    if (ngx_strlen(path) == 0) {

        /*
            If the est_ca_serial_number directive is not defined within the location 
            configuration, fall back to create a serial number based upon the root 
            certificate file name (which must be supplied for EST operations).
        */

        ngx_snprintf((u_char *)path, sizeof(path), 
                "%*s", 
                lcf->ca_root_certificate.len, 
                lcf->ca_root_certificate.data);
        ptr = strrchr(path, '.');
        length = (ptr != NULL) ? (size_t)(ptr - path) : strlen(path);
        ngx_cpystrn((u_char *)(path + length), (u_char *)_X509_SERIAL_NUMBER_EXTENSION, sizeof(path) - length);
    }

    val = NULL;
    if ((num = _ngx_http_est_x509_serial_load(path)) == NULL) {
        return NULL;
    }
    if (BN_add_word(num, 1)) {
        _ngx_http_est_x509_serial_save(path, num, &val);
    }
    BN_free(num);
    return val;
}


static ngx_int_t 
_ngx_http_est_x509_serial_save(const char *path, const BIGNUM *value, ASN1_INTEGER **asn_value) {
    ASN1_INTEGER *val;
    BIO *out;
    int ret;

    val = NULL;
    ret = -1;

    out = BIO_new_file(path, "w");
    if (out == NULL) {
        return ret;
    }
    if ((val = BN_to_ASN1_INTEGER(value, NULL)) != NULL) {
        i2a_ASN1_INTEGER(out, val);
        BIO_puts(out, "\n");

        if (asn_value != NULL) {
            *asn_value = val;
            val = NULL;
        }
        ret = 0;
    }
    ASN1_INTEGER_free(val);
    BIO_free_all(out);
    return ret;
}


X509 *
ngx_http_est_x509_generate(ngx_http_request_t *r, X509_REQ *req) {
    ngx_http_est_loc_conf_t *lcf;
    ASN1_INTEGER *serial;
    ASN1_OBJECT *obj;
    EVP_PKEY *pkey;
    STACK_OF(X509_EXTENSION) *exts;
    X509 *cacert, *cert;
    X509_EXTENSION *ext;
    X509_NAME *subj;
    char *s;
    int i, j;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    
    /*
        The following actions to verify the signature associated with the client-
        supplied certificate signing request (CSR) are performed elsewhere in this 
        code base prior to this point.
    */

    pkey = NULL;
    serial = NULL;

    if ((cacert = _ngx_http_est_x509_cacert(r)) == NULL) {
        return NULL;
    }
    if ((cert = X509_new()) == NULL) {
        return NULL;
    }
    if (!X509_set_version(cert, X509_VERSION_3)) {
        goto error;
    }

    /* assert(ngx_http_est_x509_verify(req)); */
    subj = X509_REQ_get_subject_name(req);
    if ((subj == NULL) ||
            (!X509_set_subject_name(cert, subj))) {
        goto error;
    }
    pkey = X509_REQ_get0_pubkey(req);
    if ((pkey == NULL) ||
            (!X509_set_pubkey(cert, pkey))) {
        goto error;
    }

    /*
        The following block of code copies requested extensions from the CSR into 
        the generated certificate. This code may be expanded in the future to limit 
        the extensions that can be requested by EST clients and included in 
        certificates.
    */

    exts = X509_REQ_get_extensions(req);
    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ext = sk_X509_EXTENSION_value(exts, i);
        /* assert(ext != NULL); */
        obj = X509_EXTENSION_get_object(ext);
        /* assert(obj != NULL); */
        j = X509_get_ext_by_OBJ(cert, obj, -1);
        if (j != -1) {
            do {
                X509_EXTENSION_free(X509_delete_ext(cert, j));
                j = X509_get_ext_by_OBJ(cert, obj, -1);
            }
            while (j != -1);
        }
        X509_add_ext(cert, ext, -1);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    /* assert(cacert != NULL); */
    subj = X509_get_subject_name(cacert);
    if ((subj == NULL) ||
            (!X509_set_issuer_name(cert, subj))) {
        goto error;
    }

    if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL) {
        goto error;
    }
    if (X509_time_adj_ex(X509_getm_notAfter(cert), lcf->ca_validity_days, 0, NULL) == NULL) {
        goto error;
    }

    serial = _ngx_http_est_x509_serial_number(r);
    if (serial != NULL) {
        X509_set_serialNumber(cert, serial);
    }

    if ((pkey = _ngx_http_est_x509_privkey(r)) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: error opening private key: \"%*s\"",
                MODULE_NAME,
                lcf->ca_private_key.len,
                lcf->ca_private_key.data);
        goto error;
    }
    if (!X509_check_private_key(cacert, pkey)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: private key does not match CA certificate: \"%*s\"",
                MODULE_NAME,
                lcf->ca_private_key.len,
                lcf->ca_private_key.data);
        goto error;
    }

    if (!X509_sign(cert, pkey, EVP_sha256())) {
        goto error;
    }

    EVP_PKEY_free(pkey);
    ASN1_INTEGER_free(serial);

    s = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    if (s != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "%s: certificate: \"%s\", subject: \"%s\"",
                MODULE_NAME,
                i2s_ASN1_INTEGER(NULL, X509_get0_serialNumber(cert)),
                s);
        OPENSSL_free(s);
    }

    return cert;

error:
    EVP_PKEY_free(pkey);
    ASN1_INTEGER_free(serial);
    X509_free(cert);

    return NULL;
}


ngx_int_t
ngx_http_est_x509_verify(X509_REQ *req) {
    EVP_PKEY *pkey;

    if (((pkey = X509_REQ_get0_pubkey(req)) == NULL) ||
            (!X509_REQ_verify(req, pkey))) {
        return 0;
    }
    return (X509_REQ_get_subject_name(req) != NULL);
}
