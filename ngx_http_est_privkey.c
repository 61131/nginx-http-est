#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/objects.h>

#include "ngx_http_est.h"

#define _PKCS8_RSA_BITS         (2048)


EVP_PKEY * 
ngx_http_est_privkey(ngx_http_request_t *r, X509_REQ *req) {
    EC_GROUP *group;
    EC_KEY *ec;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ctx;
    const EVP_PKEY_ASN1_METHOD *meth;
    int id, nid;

    /*
        This function is intended to generate a new private key which can be used in 
        association with server-side key generation operations provided by the EST 
        server.
    */

    ctx = NULL;
    ec = NULL;
    group = NULL;
    pkey = NULL;

    if (0) {    //  Generate EC key
        nid = NID_X9_62_prime256v1;
        if ((group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
            goto error;
        }
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);

        if ((ec = EC_KEY_new()) == NULL) {
            goto error;
        }
        if (!EC_KEY_set_group(ec, group)) {
            goto error;
        }
        if (!EC_KEY_generate_key(ec)) {
            goto error;
        }

        if ((pkey = EVP_PKEY_new()) == NULL) {
            goto error;
        }
        EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec);
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    else {      //  Generate RSA key, 2048 bits
        meth = EVP_PKEY_asn1_find_str(NULL, "rsa", -1);
        EVP_PKEY_asn1_get0_info(&id, NULL, NULL, NULL, NULL, meth);
        ctx = EVP_PKEY_CTX_new_id(id, NULL);
        if (EVP_PKEY_keygen_init(ctx) < 1) {
            goto error;
        }
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, _PKCS8_RSA_BITS);
    }

    if (EVP_PKEY_keygen_init(ctx) < 1) {
        goto error;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) < 1) {
        goto error;
    }

error:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }
    else if (ec != NULL) {
        EC_KEY_free(ec);
    }
    EC_GROUP_free(group);

    return pkey;
}

