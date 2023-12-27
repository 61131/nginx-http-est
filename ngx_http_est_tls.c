#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/ssl.h>

#define NGX_HTTP_EST_TLS_UNIQUE         (128)


ngx_int_t
ngx_http_est_tls_unique(ngx_http_request_t *r, ngx_str_t *s) {
    ngx_connection_t *c;
    ngx_str_t src;
    u_char buf[NGX_HTTP_EST_TLS_UNIQUE];
    size_t length;

    if (!r->connection->ssl) {
        return NGX_ERROR;
    }

    c = r->connection;
    if (SSL_session_reused(c->ssl->connection)) {
        length = SSL_get_finished(c->ssl->connection, buf, sizeof(buf));
    }
    else {
        length = SSL_get_peer_finished(c->ssl->connection, buf, sizeof(buf));
    }
    if (length == 0) {
        s->len = 0;
        return NGX_OK;
    }
    src.data = buf;
    src.len = length;

    /* assert(s != NULL); */
    s->len = ngx_base64_encoded_length(src.len);
    s->data = ngx_pcalloc(r->pool, s->len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }
    ngx_encode_base64(s, &src); 
    return NGX_OK;
}

