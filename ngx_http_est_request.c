#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "ngx_http_est.h"


static ngx_buf_t * _ngx_http_est_request_body(ngx_http_request_t *r);

static X509_REQ * _ngx_http_est_request_parse_csr(ngx_http_request_t *r);

static void _ngx_http_est_request_serverkeygen(ngx_http_request_t *r);

static void _ngx_http_est_request_simple(ngx_http_request_t *r);


static ngx_buf_t *
_ngx_http_est_request_body(ngx_http_request_t *r) {
    ngx_buf_t *b;
    ngx_chain_t *in;
    size_t len;

    /*
        This function is intended to return the HTTP request body in a single buffer 
        for subsequent processing operations. Returns pointer to ngx_buf_t structure
        on success, NULL on failure.
    */

    len = 0;
    for (in = r->request_body->bufs; in; in = in->next) {
        len += ngx_buf_size(in->buf);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b != NULL) {
        for (in = r->request_body->bufs; in; in = in->next) {
            b->last = ngx_cpymem(b->last, in->buf->pos, ngx_buf_size(in->buf));
        }
    }
    return b;
}


static X509_REQ *
_ngx_http_est_request_parse_csr(ngx_http_request_t *r) {
    ngx_http_est_loc_conf_t *lcf;
    ngx_array_t attributes;
    ngx_buf_t *body;
    ASN1_BIT_STRING *bs;
    ASN1_TYPE *type;
    BIO *b64, *mem;
    BUF_MEM *buf;
    X509_ATTRIBUTE *attr;
    X509_REQ *req;
    ngx_uint_t i, j;
    ngx_int_t index;
    ngx_str_t cp;
    size_t length;
    char *pp;
    int ret;

    req = NULL;
    b64 = mem = NULL;
    buf = NULL;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    if ((r->request_body == NULL) ||
            (r->request_body->bufs == NULL)) {
        return NULL;
    }
    if ((body = _ngx_http_est_request_body(r)) == NULL) {
        return NULL;
    }

    /*
        The use of OpenSSL BIO functions for base64 is specifically so that invalid 
        (non-base64 encoded) bytes in the stream, such as the "BEGIN CERTIFICATE 
        REQUEST" header and trailer lines, are silently ignored. The presence of 
        such bytes within the request payload causes the internal nginx base64 
        decoding functions to abort stream processing.
    */

    if ((mem = BIO_new_mem_buf(body->start, ngx_buf_size(body))) == NULL) {
        return NULL;
    }
    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        goto error;
    }
    mem = BIO_push(b64, mem);

    if (!d2i_X509_REQ_bio(mem, &req)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: error parsing certificate request",
                MODULE_NAME);
        X509_REQ_free(req);
        req = NULL;

        goto error;
    }
    /* assert(req != NULL); */
    if (!ngx_http_est_x509_verify(req)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: error verifying certificate request",
                MODULE_NAME);
        X509_REQ_free(req);
        req = NULL;

        goto error;
    }

    /*
        If the EST server is configured to require the client to demonstrate proof-
        of-possession of the CSR private key, the challengePassword attribute in the 
        CSR should be validated.
    */

    if (lcf->pop) {
        if (ngx_http_est_tls_unique(r, &cp) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "%s: error retrieving TLS handshake information",
                    MODULE_NAME);
            X509_REQ_free(req);
            req = NULL;

            goto error;
        }

        index = X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword, -1);
        if (index < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "%s: challengePassword attribute missing from certificate request",
                    MODULE_NAME);
            X509_REQ_free(req);
            req = NULL;

            goto error;
        }
        attr = X509_REQ_get_attr(req, index);
        /* assert(attr != NULL); */
        type = X509_ATTRIBUTE_get0_type(attr, 0);
        /* assert(type != NULL); */
        bs = type->value.asn1_string;
        /* assert(bs != NULL); */
        if ((bs->length != (int) cp.len) ||
                (memcmp(bs->data, cp.data, bs->length) != 0)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "%s: invalid challengePassword attribute in certificate request",
                    MODULE_NAME);
            X509_REQ_free(req);
            req = NULL;

            goto error;
        }
    }

    BIO_reset(mem);
    if ((buf = BUF_MEM_new()) == NULL) {
        goto error;
    }
    for (length = 0;;) {
        if (!BUF_MEM_grow(buf, BUFSIZ + length)) {
            goto error;
        }
        ret = BIO_read(mem, &(buf->data[length]), BUFSIZ);
        if (ret <= 0) {
            break;
        }
        length += ret;
    }

    pp = buf->data;
    ngx_array_init(&attributes, r->pool, 8, sizeof(ngx_str_t));
    if (ngx_http_est_asn1_parse(&attributes, (const unsigned char **) &pp, length, 0) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: error parsing certificate attributes",
                MODULE_NAME);
        X509_REQ_free(req);
        req = NULL;

        goto error;
    }

    /*
        If there are mandatory attributes defined for certificate signing requests, 
        the submitted signing request will be validated with respect to the 
        inclusion of these attributes. It is noted that this is an O(n*m) operation, 
        but that this performance should be acceptable given the pre-parsing of 
        attributes from the ASN.1 certificate byte sequence.

        Note that lcf->attributes is only defined if the est_csr_attrs directive is
        included in the location directive.
    */

    if (lcf->attributes != NULL) {  
        for (i = 0; i < lcf->attributes->nelts; ++i) {
            ret = -1;
            for (j = 0; j < attributes.nelts; ++j) {
                if ((ret = ngx_strcmp(((ngx_str_t *)lcf->attributes->elts)[i].data,
                        ((ngx_str_t *)attributes.elts)[j].data)) == 0) {
                    break;
                }
            }
            if (ret != 0) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "%s: certificate signing request missing mandatory attribute: \"%*s\"",
                        MODULE_NAME,
                        ((ngx_str_t *)lcf->attributes->elts)[i].len,
                        ((ngx_str_t *)lcf->attributes->elts)[i].data);
                X509_REQ_free(req);
                req = NULL;

                goto error;
            }
        }
    }

error:
    BUF_MEM_free(buf);
    BIO_free_all(mem);

    return req;
}


static void 
_ngx_http_est_request_serverkeygen(ngx_http_request_t *r) {
    X509_REQ *req;
    ngx_int_t rc;

    rc = NGX_HTTP_BAD_REQUEST;

    /*
        This function implements handling for the HTTP request body submitted to 
        the EST API end-point for certificate and server-side key generation. This 
        is performed by reading and parsing the Certificate Signing Request (CSR) 
        contained in the request body and validating this per local configuration 
        in the same manner as is performed for simple certificate enrollment and 
        re-enrollment requests. The difference with this function is that the 
        public key associated with the submitted CSR is replaced entirely with a 
        newly generated key. The new certificate and private key is then returned 
        to the client.
    */

    if ((req = _ngx_http_est_request_parse_csr(r)) == NULL) {
        goto error;
    }

error:
    X509_REQ_free(req);

    ngx_http_finalize_request(r, rc);
}


static void
_ngx_http_est_request_simple(ngx_http_request_t *r) {
    BIO *pem, *pkcs7;
    BUF_MEM *ptr;
    PKCS7 *p7;
    X509_REQ *req;
    X509 *cert;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_int_t rc;
    u_char *content;
    size_t length;

    /*
        This function implements handling for HTTP request bodies submitted to the 
        EST API end-point for certificate generation. This is performed by reading 
        and parsing the Certificate Signing Request (CSR) contained in the request 
        body, validating this as per local configuration and generating the new 
        certificate from the back-end certificate authority.
    */

    rc = NGX_HTTP_BAD_REQUEST;
    pem = pkcs7 = NULL;
    cert = NULL;
    p7 = NULL;

    if ((req = _ngx_http_est_request_parse_csr(r)) == NULL) {
        goto error;
    }
    if ((cert = ngx_http_est_x509_generate(r, req)) == NULL) {
        goto error;
    }
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "%s: certificate: \"%s\", subject: \"%s\"",
            MODULE_NAME,
            i2s_ASN1_INTEGER(NULL, X509_get0_serialNumber(cert)),
            X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));

    /*
        The following code will write the newly generated certificate into a memory 
        buffer in a PEM format which in turn is then read in in a pkcs7 format.
    */

    if (((pem = BIO_new(BIO_s_mem())) == NULL) ||
            (!PEM_write_bio_X509(pem, cert))) {
        goto error;
    }
    /* length = BIO_get_mem_data(pem, &pp); */
    BIO_seek(pem, 0);
    if ((p7 = ngx_http_est_pkcs7(pem)) == NULL) {
        goto error;
    }
    if (((pkcs7 = BIO_new(BIO_s_mem())) == NULL) ||
            (!PEM_write_bio_PKCS7(pkcs7, p7))) {
        goto error;
    }

    BIO_get_mem_ptr(pkcs7, &ptr);
    /* assert(ptr != NULL); */
    /* assert(ptr->length > 42); */
    /* assert(ngx_strncmp(ptr->data, "-----BEGIN PKCS7-----\n", 22) == 0); */
    /* assert(ngx_strncmp(..., "-----END PKCS7-----\n", 20) == 0); */
    length = ptr->length - 42;
    if ((content = ngx_pcalloc(r->pool, length)) == NULL) {
        goto error;
    }
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        goto error;
    }
    b->pos = b->last = content;
    b->memory = 1;
    b->last = ngx_copy(b->last, ptr->data + 22, length);
    b->last_buf = (r == r->main) ? 1 : 0;

    out.buf = b;
    out.next = NULL;

    r->headers_out.content_type_len = sizeof("application/pkcs7-mime") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/pkcs7-mime");
    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if ((r->header_only) ||
            (rc == NGX_ERROR) ||
            (rc > NGX_OK)) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    rc = ngx_http_output_filter(r, &out);
error:
    PKCS7_free(p7);
    BIO_free(pkcs7);
    BIO_free(pem);
    X509_free(cert);
    X509_REQ_free(req);

    ngx_http_finalize_request(r, rc);
}


ngx_int_t
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

    if ((!r->connection->ssl) &&
            (lcf->http == HTTP_DISALLOW)) { 
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

    /*
        Determine whether the requested EST API end-point is supported for the given 
        HTTP method and SSL client verification state. Note that HTTP-based 
        authorization, if configured and required for an operation end-point, is 
        verified in the access phase handler (ngx_http_est_auth).
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

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s: \"%*s\"", 
                MODULE_NAME,
                ngx_strlen(uri),
                uri);

        /*
            The following code implements controls around access to certain EST end-
            points based upon (client certificate) verification status (as HTTP
            authentication access is verified within the ACCESS_PHASE handler) and 
            whether the request has been received via unsecured HTTP (where access to 
            verified functions is only permitted via HTTPS).
        */

        if (!d->verify) {
            break;
        }
        if ((!r->connection->ssl) &&
              (lcf->http == HTTP_LIMIT)) { 
            return NGX_HTTP_NOT_ALLOWED;
        }
        if ((lcf->verify_client & VERIFY_CERTIFICATE) != 0) {
            if (!r->connection->ssl) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                        "%s: cannot verify certificate as client using non-secure connection",
                        MODULE_NAME);
                return NGX_HTTP_FORBIDDEN;
            }

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
    b->last_buf = (r == r->main) ? 1 : 0;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if ((r->header_only) ||
            (rc == NGX_ERROR) ||
            (rc > NGX_OK)) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


ngx_int_t 
ngx_http_est_request_cacerts(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_http_est_loc_conf_t *lcf;
    BIO *bp;
    BUF_MEM *ptr;
    u_char *content;
    size_t length;
    int rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    if (lcf == NULL) {
        return NGX_DECLINED;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/pkcs7-mime") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/pkcs7-mime");

    rc = NGX_ERROR;
    if (((bp = BIO_new(BIO_s_mem())) == NULL) ||
            (!PEM_write_bio_PKCS7(bp, lcf->root))) {
        goto error;
    }

    /*
        The following code will strip the PKCS7 certificate header and footer, 
        leaving only the base64 encoded bytes, to ensure compatibility with 
        different EST clients.
    */

    BIO_get_mem_ptr(bp, &ptr);
    /* assert(ptr != NULL); */
    /* assert(ptr->length > 42); */
    /* assert(ngx_strncmp(ptr->data, "-----BEGIN PKCS7-----\n", 22) == 0); */
    /* assert(ngx_strncmp(..., "-----END PKCS7-----\n", 20) == 0); */
    length = ptr->length - 42;
    if ((content = ngx_pcalloc(r->pool, length)) == NULL) {
        goto error;
    }
    b->pos = b->last = content;
    b->memory = 1;
    b->last = ngx_copy(b->last, ptr->data + 22, length);

    rc = NGX_OK;

error:
    BIO_free(bp);
    return rc;
}


ngx_int_t 
ngx_http_est_request_csrattrs(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_http_est_loc_conf_t *lcf;
    ngx_str_t str, res;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_est_module);
    /* assert(lcf != NULL); */
    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_type_len = sizeof("application/csrattrs") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/csrattrs");

    if ((lcf->buf != NULL) &&
            (lcf->buf->length > 0)) {
        str.len = lcf->buf->length;
        str.data = (u_char *)lcf->buf->data;
        res.len = ngx_base64_encoded_length(str.len);
        res.data = ngx_pcalloc(r->pool, res.len + 2);
        if (res.data == NULL) {
            return NGX_ERROR;
        }
        ngx_encode_base64(&res, &str);
        b->pos = b->last = res.data;
        b->memory = 1;
        b->last += res.len;
        b->last = ngx_copy(b->last, CRLF, 2);

        r->headers_out.status = NGX_HTTP_OK;
    }

    return NGX_OK;
}


ngx_int_t 
ngx_http_est_request_not_implemented(ngx_http_request_t *r, ngx_buf_t *b) {
    return NGX_HTTP_NOT_IMPLEMENTED;
}


ngx_int_t 
ngx_http_est_request_simple_request(ngx_http_request_t *r, ngx_buf_t *b) {
    ngx_http_core_loc_conf_t *clcf;
    ngx_str_t value;
    ngx_int_t rc;
    u_char *ptr;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_DECLINED;
    }

    /*
        This function will process the request headers before establishing a 
        callback handler to processing the request body which is expected to 
        contain the certificate signing request (CSR) associated with the 
        /simpleenroll, /simplereenroll or /serverkeygen request. It should be noted 
        that different callback functions are employed depending upon whether the 
        request is for certificate (re-)enrollment or certificate enrollment with 
        server-side key generation.
    */

    /* assert(r->method == NGX_HTTP_POST); */
    if ((r->headers_in.content_type == NULL) ||
            (r->headers_in.content_type->value.data == NULL)) {
        return NGX_HTTP_BAD_REQUEST;
    }
    value = r->headers_in.content_type->value;
    if (ngx_strcasecmp(value.data, (u_char *) "application/pkcs10") != 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    ptr = r->uri.data;
    /* assert(ngx_strstr(ptr, clcf->name.data) == (char *) ptr); */
    ptr += ngx_strlen(clcf->name.data);
    if (*ptr == '/') {
        ++ptr;
    }
    rc = ngx_http_read_client_request_body(r,
            (ngx_strncmp(ptr, "serverkeygen", 12) == 0) ?   //  NB: ptr is not '\0' terminated!
                    _ngx_http_est_request_serverkeygen :
                    _ngx_http_est_request_simple);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_OK;
}


