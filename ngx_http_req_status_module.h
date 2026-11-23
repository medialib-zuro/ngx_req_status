#ifndef _NGX_HTTP_REQ_STATUS_MODELE_H_INCLUDED_
#define _NGX_HTTP_REQ_STATUS_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_uint_t ngx_http_req_status_get_current_bw(ngx_http_request_t *r);
ngx_uint_t ngx_http_req_status_get_current_conns(ngx_http_request_t *r);

#endif //_NGX_HTTP_REQ_STATUS_MODELE_H_INCLUDED_
