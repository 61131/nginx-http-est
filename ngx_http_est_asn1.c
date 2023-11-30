#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include "ngx_http_est.h"


ngx_int_t
ngx_http_est_asn1_parse(ngx_array_t *array, const unsigned char **data, size_t length, off_t offset) {
    ASN1_OBJECT *obj;
    ngx_str_t *attribute;
    const unsigned char *end, *p1, *p2, *p3, *p4;
    char buf[128];
    int class, header, ret, tag, val;
    long len;

    /*
        This function is intended to parse through an ASN.1 structure, identifying 
        object identifiers contained therein. This function has been drawn from the 
        libest library within which the corresponding function has been derived from 
        the OpenSSL library. 
    */

    obj = NULL;
    p1 = *data;
    end = p1 + length;
    p2 = p1 - 1;

    while ((p1 < end) && (p2 < p1)) {
        p2 = p1;
        val = ASN1_get_object(&p1, &len, &tag, &class, length);
        if (val & 0x80) {
            *data = p1;
            return -1;
        }
        header = p1 - p2;
        length -= header;

        if (val & V_ASN1_CONSTRUCTED) {
            p3 = p1 + len;
            if (len > (long)length) {
                *data = p1;
                return -1;
            }
            if ((val == 0x21) && 
                    (len == 0)) {
                ret = ngx_http_est_asn1_parse(array, &p1, (size_t)(end - p1), offset + (p1 - *data));
                if (ret < 0) { 
                    *data = p1;
                    return -1;
                }
                if (p1 >= end) {
                    break;
                }
            } else {
                while (p1 < p3) {
                    ret = ngx_http_est_asn1_parse(array, &p1, (size_t)len, offset + (p1 - *data));
                    if (ret < 0) { 
                        *data = p1;
                        return -1;
                    }
                }
            }
        }
        else if (class != 0) {
            p1 += len;
        }
        else {
            if (tag == V_ASN1_OBJECT) {
                p4 = p2;
                if (d2i_ASN1_OBJECT(&obj, &p4, len + header) == NULL) {
                    ASN1_OBJECT_free(obj);
                    *data = p1;
                    return -1;
                }
                i2t_ASN1_OBJECT(buf, sizeof(buf), obj);
                /* assert(strlen(buf) > 0); */

                attribute = ngx_array_push(array);
                if (attribute == NULL) {
                    goto error;
                }
                attribute->len = strlen(buf) + 1;
                attribute->data = ngx_pnalloc(array->pool, attribute->len);
                if (attribute->data == NULL) {
                    goto error;
                }
                (void) ngx_copy(attribute->data, buf, strlen(buf));

                ASN1_OBJECT_free(obj);
            }
            p1 += len;
            if ((tag == V_ASN1_EOC) &&
                    (class == 0)) {
                *data = p1;
                return 0;
            }
        }
        length -= len;
    }
    *data = p1;
    return 0;

error:
    ASN1_OBJECT_free(obj);
    return -1;
}


