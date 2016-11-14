/*
 * Copyright 2016 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef _NGX_TOKEN_BINDING_H_INCLUDED_
#define _NGX_TOKEN_BINDING_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_TOKEN_BINDING_HMAC_LENGTH  43


ngx_int_t ngx_token_binding_init(ngx_conf_t *cf);

ngx_int_t ngx_token_binding_enable(ngx_conf_t *cf, ngx_ssl_t *ssl);

ngx_int_t ngx_token_binding_negotiated(ngx_connection_t *c);
ngx_int_t ngx_token_binding_verify(ngx_connection_t *c, ngx_str_t *message,
    ngx_str_t *provided, ngx_str_t *referred);

ngx_int_t ngx_token_binding_hash(ngx_str_t *id, ngx_str_t *out,
    ngx_pool_t *pool);
void ngx_token_binding_key_type(ngx_str_t *id, ngx_str_t *out);

ngx_int_t ngx_token_binding_calculate_hmac(ngx_str_t *key, ngx_array_t *data,
    ngx_str_t *out, ngx_pool_t *pool);


#endif /* _NGX_TOKEN_BINDING_H_INCLUDED_ */
