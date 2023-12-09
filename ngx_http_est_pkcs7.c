#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "ngx_http_est.h"


PKCS7 *
ngx_http_est_pkcs7(BIO *bp) {
    PKCS7 *p7;
    PKCS7_SIGNED *p7s;
    STACK_OF(X509) *stack;
    STACK_OF(X509_INFO) *sk;
    X509_INFO *info;
    int ret;

    /*
        This function is intended to convert a PEM encoded X.509 certificate into 
        PKCS7 certificate structure for return to EST clients.
    */

    sk = NULL;
    ret = -1;

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

    /* assert(bp != NULL); */
    if ((sk = PEM_X509_INFO_read_bio(bp, NULL, NULL, NULL)) == NULL) {
        goto error;
    }

    while (sk_X509_INFO_num(sk)) {
        info = sk_X509_INFO_shift(sk);
        if (info->x509 != NULL) {
            sk_X509_push(p7s->cert, info->x509);
            info->x509 = NULL;
        }
        X509_INFO_free(info);
    }
    ret = 0;

error:
    sk_X509_INFO_free(sk);
    if (ret < 0) {
        PKCS7_free(p7);
        p7 = NULL;
    }
    return p7;
}
