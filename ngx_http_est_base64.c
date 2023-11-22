#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>

#include "ngx_http_est_base64.h"


u_char *
ngx_http_est_base64_decode(ngx_http_request_t *r, const char *data, size_t *length) {
    BIO *b64, *mem;
    u_char *b;

    b64 = mem = NULL;
    b = NULL;

    if (((b64 = BIO_new(BIO_f_base64())) == NULL) ||
            ((mem = BIO_new_mem_buf(data, *length)) == NULL)) {
        goto error;
    }
    mem = BIO_push(b64, mem);

    if ((b = ngx_pcalloc(r->pool, *length)) == NULL) {
        goto error;
    }
    *length = BIO_read(mem, b, *length);

error:
    BIO_free_all(mem);
    return b;
}


u_char * 
ngx_http_est_base64_encode(ngx_http_request_t *r, const char *data, size_t *length) {
    BIO *b64, *mem;
    BUF_MEM *ptr;
    u_char *b;

    b64 = mem = NULL;
    b = NULL;

    if (((b64 = BIO_new(BIO_f_base64())) == NULL) ||
            ((mem = BIO_new(BIO_s_mem())) == NULL)) {
        goto error;
    }
    mem = BIO_push(b64, mem);

    if (BIO_write(mem, data, *length) < 0) {
        goto error;
    }
    BIO_flush(mem);
    BIO_get_mem_ptr(mem, &ptr);
    /* assert(ptr != NULL); */

    if ((b = ngx_pcalloc(r->pool, ptr->length)) == NULL) {
        goto error;
    }
    (void) ngx_copy(b, ptr->data, ptr->length);
    *length = ptr->length;

error:
    BIO_free_all(mem);
    return b;
}


