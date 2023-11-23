#ifndef _NGX_HTTP_EST_BASE64_H_INCLUDED_
#define _NGX_HTTP_EST_BASE64_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


u_char * ngx_http_est_base64_decode(ngx_http_request_t *r, const char *data, size_t *length);

u_char * ngx_http_est_base64_encode(ngx_http_request_t *r, const char *data, size_t *length);


#endif  /* _NGX_HTTP_EST_BASE64_H_INCLUDED_ */
