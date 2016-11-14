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


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_token_binding_module.h>


typedef struct {
    ngx_flag_t    enabled;

    ngx_str_t     cookies_secret;
    ngx_flag_t    cookies_all;
    ngx_array_t  *cookies;

    u_char       *enabled_conf_file;
    ngx_uint_t    enabled_conf_line;
    u_char       *cookies_conf_file;
    ngx_uint_t    cookies_conf_line;
} ngx_http_token_binding_srv_conf_t;


#define ngx_http_token_binding_str_set_id(s)                                  \
    (s)->data = r->variables[ngx_http_token_binding_provided_id_index].data;  \
    (s)->len = r->variables[ngx_http_token_binding_provided_id_index].len;

static ngx_int_t ngx_http_token_binding_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_token_binding_process_cookie_header(
    ngx_http_request_t *r, ngx_table_elt_t *header);

static ngx_int_t ngx_http_token_binding_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_token_binding_process_set_cookie_header(
    ngx_http_request_t *r, ngx_table_elt_t *header);

static ngx_int_t ngx_http_token_binding_parse_cookie(ngx_str_t *in,
    ngx_keyval_t *cookie, ngx_str_t *rest);
static ngx_int_t ngx_http_token_binding_configured_cookie(ngx_http_request_t *r,
    ngx_str_t *key);

static ngx_int_t ngx_http_token_binding_raw_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_token_binding_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_token_binding_key_type_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_token_binding_preinit(ngx_conf_t *cf);
static void *ngx_http_token_binding_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_token_binding_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_token_binding_init(ngx_conf_t *cf);

static char *ngx_http_token_binding_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_token_binding_cookie(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_token_binding_commands[] = {

    { ngx_string("token_binding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_http_token_binding_enable,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_token_binding_srv_conf_t, enabled),
      NULL },

    { ngx_string("token_binding_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_token_binding_cookie,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("token_binding_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_token_binding_srv_conf_t, cookies_secret),
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_token_binding_module_ctx = {
    ngx_http_token_binding_preinit,          /* preconfiguration */
    ngx_http_token_binding_init,             /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    ngx_http_token_binding_create_srv_conf,  /* create server configuration */
    ngx_http_token_binding_merge_srv_conf,   /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};


ngx_module_t  ngx_http_token_binding_module = {
    NGX_MODULE_V1,
    &ngx_http_token_binding_module_ctx,      /* module context */
    ngx_http_token_binding_commands,         /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_uint_t  ngx_http_token_binding_provided_id_index;
static ngx_uint_t  ngx_http_token_binding_referred_id_index;


static ngx_http_variable_t  ngx_http_token_binding_vars[] = {

    { ngx_string("provided_token_binding_raw_id"), NULL,
      ngx_http_token_binding_raw_id_variable,
      0, 0, 0 },

    { ngx_string("referred_token_binding_raw_id"), NULL,
      ngx_http_token_binding_raw_id_variable,
      0, 0, 0 },

    { ngx_string("provided_token_binding_id"), NULL,
      ngx_http_token_binding_id_variable,
      (uintptr_t) &ngx_http_token_binding_provided_id_index,
      0, 0 },

    { ngx_string("referred_token_binding_id"), NULL,
      ngx_http_token_binding_id_variable,
      (uintptr_t) &ngx_http_token_binding_referred_id_index,
      0, 0 },

    { ngx_string("provided_token_binding_key_type"), NULL,
      ngx_http_token_binding_key_type_variable,
      (uintptr_t) &ngx_http_token_binding_provided_id_index,
      0, 0 },

    { ngx_string("referred_token_binding_key_type"), NULL,
      ngx_http_token_binding_key_type_variable,
      (uintptr_t) &ngx_http_token_binding_referred_id_index,
      0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_token_binding_handler(ngx_http_request_t *r)
{
    ngx_str_t                           decoded, provided, referred;
    ngx_uint_t                          tls_ok, http_ok, i;
    ngx_list_part_t                    *part;
    ngx_table_elt_t                    *header, **cookie;;
    ngx_http_variable_value_t          *vv;
    ngx_http_token_binding_srv_conf_t  *tbscf;

    static ngx_str_t  token_binding_name = ngx_string("sec-token-binding");

    static ngx_uint_t token_binding_hash =
        ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(
        ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(
        's', 'e'), 'c'), '-'), 't'), 'o'), 'k'), 'e'), 'n'), '-'), 'b'), 'i'),
        'n'), 'd'), 'i'), 'n'), 'g');

    tbscf = ngx_http_get_module_srv_conf(r, ngx_http_token_binding_module);

    if (!tbscf->enabled) {
        return NGX_DECLINED;
    }

    /* check if Token Binding was negotiated during TLS handshake */

    if (ngx_token_binding_negotiated(r->connection) == NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Token Binding was negotiated");
        tls_ok = 1;

    } else {
        tls_ok = 0;
    }

    /* find "Sec-Token-Binding" header */

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                http_ok = 0;
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].value.len == 0) {
            continue;
        }

        if (token_binding_hash == header[i].hash
            && token_binding_name.len == header[i].key.len
            && ngx_strncmp(token_binding_name.data, header[i].lowcase_key,
                           token_binding_name.len)
               == 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "Token Binding message was found");
            http_ok = 1;
            break;
        }
    }

    /* verify that we have neither or both of the Token Binding indicators */

    if (tls_ok != http_ok) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "Token Binding %s negotiated, but Token Binding message"
                      " %s found in the HTTP request headers",
                      tls_ok ? "was" : "wasn't", http_ok ? "was" : "wasn't");

        return NGX_HTTP_BAD_REQUEST;
    }

    if (!tls_ok) {
        ngx_str_null(&provided);
        goto cookies;
    }

    /* verify Token Binding message */

    decoded.len = ngx_base64_decoded_length(header[i].value.len);

    decoded.data = ngx_pnalloc(r->pool, decoded.len);
    if (decoded.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_decode_base64url(&decoded, &header[i].value) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "Token Binding message decoding failed");

        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_token_binding_verify(r->connection, &decoded, &provided, &referred)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "Token Binding message verification failed");

        return NGX_HTTP_BAD_REQUEST;
    }

    /* remove "Sec-Token-Binding" header */

    ngx_str_null(&header[i].value);
    header[i].hash = 0;

    /* save Token Binding IDs in variables */

    vv = &r->variables[ngx_http_token_binding_provided_id_index];

    if (provided.data) {
        vv->data = provided.data;
        vv->len = provided.len;

        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;

    } else {
        vv->not_found = 1;
    }

    vv = &r->variables[ngx_http_token_binding_referred_id_index];

    if (referred.data) {
        vv->data = referred.data;
        vv->len = referred.len;

        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;

    } else {
        vv->not_found = 1;
    }

cookies:

    /* decrypt Cookies */

    if (!tbscf->cookies_all && tbscf->cookies == NULL) {
        return NGX_DECLINED;
    }

    cookie = r->headers_in.cookies.elts;

    for (i = 0; i < r->headers_in.cookies.nelts; i++) {

        if (ngx_http_token_binding_process_cookie_header(r, cookie[i])
            == NGX_ERROR)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_token_binding_process_cookie_header(ngx_http_request_t *r,
    ngx_table_elt_t *header)
{
    size_t                              len;
    u_char                             *p, *start, *expected;
    ngx_str_t                          *part, rest, hmac;
    ngx_uint_t                          i, rewrite;
    ngx_array_t                        *data, cookies;
    ngx_keyval_t                       *cookie;
    ngx_http_token_binding_srv_conf_t  *tbscf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Token Binding processing header: \"%V: %V\"",
                   &header->key, &header->value);

    if (ngx_array_init(&cookies, r->pool, 8, sizeof(ngx_keyval_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    rest = header->value;

    while (rest.len) {

        cookie = ngx_array_push(&cookies);
        if (cookie == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_token_binding_parse_cookie(&rest, cookie, &rest)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "Token Binding failed to parse header: \"%V: %V\"",
                          &header->key, &header->value);
            goto remove;
        }
    }

    len = 0;
    data = NULL;
    rewrite = 0;

    cookie = cookies.elts;

    for (i = 0; i < cookies.nelts; i++) {

        if (ngx_http_token_binding_configured_cookie(r, &cookie[i].key)
            != NGX_OK)
        {
            goto keep;
        }

        rewrite = 1;

        if (r->connection->ssl == NULL) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "Token Binding discarding cookie: \"%V\""
                          " received over an insecure channel",
                          &cookie[i].key);
            goto drop;
        }

        if (cookie[i].value.len
            < sizeof("_") - 1 + NGX_TOKEN_BINDING_HMAC_LENGTH)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "Token Binding discarding too small cookie: \"%V\"",
                          &cookie[i].key);
            goto drop;
        }

        cookie[i].value.len -= sizeof("_") - 1 + NGX_TOKEN_BINDING_HMAC_LENGTH;

        expected = cookie[i].value.data + cookie[i].value.len + sizeof("_") - 1;

        if (data == NULL) {
            data = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
            if (data == NULL) {
                return NGX_ERROR;
            }

            part = data->elts;
            data->nelts = 4;

            ngx_http_token_binding_str_set_id(&part[0]);
            ngx_str_set(&part[2], "=");

        } else {
#if (NGX_SUPPRESS_WARN)
            part = data->elts;
#endif
        }

        part[1] = cookie[i].key;
        part[3] = cookie[i].value;

        tbscf = ngx_http_get_module_srv_conf(r, ngx_http_token_binding_module);

        if (ngx_token_binding_calculate_hmac(&tbscf->cookies_secret, data,
                                             &hmac, r->pool)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (hmac.len != NGX_TOKEN_BINDING_HMAC_LENGTH
            || ngx_strncmp(expected, hmac.data, hmac.len) != 0)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "Token Binding cookie: \"%V\" verification failed",
                          &cookie[i].key);
            goto drop;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Token Binding cookie: \"%V\" verified successfully",
                       &cookie[i].key);

keep:

        if (len) {
            len += sizeof("; ") - 1;
        }

        len += cookie[i].key.len + sizeof("=") - 1 + cookie[i].value.len;

        continue;

drop:

        ngx_str_null(&cookie[i].key);
        ngx_str_null(&cookie[i].value);
    }

    if (!rewrite) {
        return NGX_OK;
    }

    if (len == 0) {
        goto remove;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    start = p;

    for (i = 0; i < cookies.nelts; i++) {

        if (cookie[i].key.len) {

            if (p != start) {
                *p++ = ';'; *p++ = ' ';
            }

            p = ngx_cpymem(p, cookie[i].key.data, cookie[i].key.len);
            *p++ = '=';
            p = ngx_cpymem(p, cookie[i].value.data, cookie[i].value.len);
        }
    }

    header->value.data = start;
    header->value.len = len;

    return NGX_OK;

remove:

    ngx_str_null(&header->value);
    header->hash = 0;

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_token_binding_filter(ngx_http_request_t *r)
{
    ngx_uint_t                          i;
    ngx_list_part_t                    *part;
    ngx_table_elt_t                    *header;
    ngx_http_token_binding_srv_conf_t  *tbscf;

    static ngx_str_t set_cookie_name = ngx_string("set-cookie");

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    tbscf = ngx_http_get_module_srv_conf(r, ngx_http_token_binding_module);

    if (!tbscf->cookies_all && tbscf->cookies == NULL) {
        return ngx_http_next_header_filter(r);
    }

    /* find all "Set-Cookie" headers */

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        /*
         * As a result of silly micro-optimizations:
         * - header[i].hash doesn't have to match the key (might be 1),
         * - header[i].lowcase_key might be NULL,
         * so we need to iterate over all headers without hash lookup.
         */

        if (header[i].hash != 0
            && set_cookie_name.len == header[i].key.len
            && ngx_strncasecmp(set_cookie_name.data, header[i].key.data,
                               set_cookie_name.len)
               == 0)
        {
            if (ngx_http_token_binding_process_set_cookie_header(r, &header[i])
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_token_binding_process_set_cookie_header(ngx_http_request_t *r,
    ngx_table_elt_t *header)
{
    size_t                              len;
    u_char                             *p;
    ngx_str_t                          *part, rest, hmac;
    ngx_uint_t                          secure;
    ngx_array_t                         data;
    ngx_keyval_t                        cookie;
    ngx_http_token_binding_srv_conf_t  *tbscf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Token Binding processing header: \"%V: %V\"",
                   &header->key, &header->value);

    if (ngx_http_token_binding_parse_cookie(&header->value, &cookie, &rest)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "Token Binding failed to parse header: \"%V: %V\"",
                      &header->key, &header->value);
        goto remove;
    }

    if (ngx_http_token_binding_configured_cookie(r, &cookie.key) != NGX_OK) {
        return NGX_OK;
    }

    if (r->connection->ssl == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "Token Binding discarding cookie: \"%V\", which"
                      " was going to be sent over an insecure channel",
                      &cookie.key);
        goto remove;
    }

    if (ngx_array_init(&data, r->pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    part = data.elts;
    data.nelts = 4;

    ngx_http_token_binding_str_set_id(&part[0]);
    part[1] = cookie.key;
    ngx_str_set(&part[2], "=");
    part[3] = cookie.value;

    tbscf = ngx_http_get_module_srv_conf(r, ngx_http_token_binding_module);

    if (ngx_token_binding_calculate_hmac(&tbscf->cookies_secret, &data, &hmac,
                                         r->pool)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    secure = 0;

    len = cookie.key.len + sizeof("=") - 1 + cookie.value.len
          + sizeof("_") - 1 + NGX_TOKEN_BINDING_HMAC_LENGTH;

    if (rest.len) {
        len += sizeof("; ") - 1 + rest.len;

        if (ngx_strlcasestrn(rest.data, rest.data + rest.len,
                             (u_char *) "Secure", sizeof("Secure") - 1 - 1)
            != NULL)
        {
            secure = 1;
        }
    }

    if (!secure) {
        len += sizeof("; ") - 1 + sizeof("Secure") - 1;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(p, cookie.key.data, cookie.key.len);
    *p ++ = '=';
    p = ngx_cpymem(p, cookie.value.data, cookie.value.len);
    *p ++ = '_';
    p = ngx_cpymem(p, hmac.data, hmac.len);

    if (rest.len) {
        *p ++ = ';'; *p ++ = ' ';
        p = ngx_cpymem(p, rest.data, rest.len);
    }

    if (!secure) {
        *p ++ = ';'; *p ++ = ' ';
        p = ngx_cpymem(p, (u_char *) "Secure", sizeof("Secure") - 1);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Token Binding cookie: \"%V\" signed successfully",
                   &cookie.key);

    header->value.data = p - len;
    header->value.len = len;

    return NGX_OK;

remove:

    ngx_str_null(&header->value);
    header->hash = 0;

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_token_binding_parse_cookie(ngx_str_t *in, ngx_keyval_t *cookie,
    ngx_str_t *rest)
{
    u_char  *p, *start, *end;

    if (in->data == NULL || in->len == 0) {
        return NGX_DECLINED;
    }

    p = start = in->data;
    end = in->data + in->len;

    for (/* void */ ; p < end && *p == ' '; p++) { /* void */ }

    if (p == end) {
        return NGX_DECLINED;
    }

    for (start = p; p < end && *p != '=' && *p != ' '; p++) { /* void */ }

    if (p == start || p == end) {
        return NGX_DECLINED;
    }

    cookie->key.data = start;
    cookie->key.len = p - start;

    for (/* void */ ; p < end && *p == ' '; p++) { /* void */ }

    if (p == end) {
        return NGX_DECLINED;
    }

    if (*p++ != '=') {
        return NGX_DECLINED;
    }

    for (/* void */ ; p < end && *p == ' '; p++) { /* void */ }

    if (p == end) {
        ngx_str_null(&cookie->value);
        ngx_str_null(rest);
        return NGX_OK;
    }

    for (start = p; p < end && *p != ';' && *p != ' '; p++) { /* void */ }

    if (p != start) {
        cookie->value.data = start;
        cookie->value.len = p - start;

        for (/* void */ ; p < end && *p == ' '; p++) { /* void */ }

        if (p == end) {
            ngx_str_null(rest);
            return NGX_OK;
        }

    } else {
        ngx_str_null(&cookie->value);
    }

    if (*p++ != ';') {
        return NGX_DECLINED;
    }

    for (/* void */ ; p < end && *p == ' '; p++) { /* void */ }

    if (p == end) {
        ngx_str_null(rest);
        return NGX_OK;
    }

    for (/* void */ ; p < end && *(end - 1) == ' '; end--) { /* void */ }

    rest->data = p;
    rest->len = end - p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_token_binding_configured_cookie(ngx_http_request_t *r,
    ngx_str_t *key)
{
    ngx_str_t                          *cookie;
    ngx_uint_t                          i;
    ngx_http_token_binding_srv_conf_t  *tbscf;

    tbscf = ngx_http_get_module_srv_conf(r, ngx_http_token_binding_module);

    if (tbscf->cookies_all) {
        return NGX_OK;
    }

    cookie = tbscf->cookies->elts;

    for (i = 0; i < tbscf->cookies->nelts; i++) {

        if (cookie[i].len == key->len
            && ngx_strncmp(cookie[i].data, key->data, key->len) == 0)
        {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_token_binding_raw_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_token_binding_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  *raw_id = (ngx_uint_t *) data;

    ngx_str_t    id, out;

    if (r->variables[*raw_id].data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    id.data = r->variables[*raw_id].data;
    id.len = r->variables[*raw_id].len;

    if (ngx_token_binding_hash(&id, &out, r->pool) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = out.data;
    v->len = out.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_token_binding_key_type_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  *raw_id = (ngx_uint_t *) data;

    ngx_str_t    id, out;

    if (r->variables[*raw_id].data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    id.data = r->variables[*raw_id].data;
    id.len = r->variables[*raw_id].len;

    ngx_token_binding_key_type(&id, &out);

    v->data = out.data;
    v->len = out.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_token_binding_preinit(ngx_conf_t *cf)
{
    ngx_int_t             index;
    ngx_http_variable_t  *var, *v;

    if (ngx_token_binding_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    for (v = ngx_http_token_binding_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    /* $provided_token_binding_raw_id */

    index = ngx_http_get_variable_index(cf,
                                        &ngx_http_token_binding_vars[0].name);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_token_binding_provided_id_index = index;

    /* $referred_token_binding_raw_id */

    index = ngx_http_get_variable_index(cf,
                                        &ngx_http_token_binding_vars[1].name);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_token_binding_referred_id_index = index;

    return NGX_OK;
}


static void *
ngx_http_token_binding_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_token_binding_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_token_binding_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->cookies_secret = { 0, NULL };
     *
     *     conf->enabled_conf_file = NULL;
     *     conf->enabled_conf_line = 0;
     *     conf->cookies_conf_file = NULL;
     *     conf->cookies_conf_line = 0;
     */

    conf->enabled = NGX_CONF_UNSET;

    conf->cookies = NGX_CONF_UNSET_PTR;
    conf->cookies_all = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_token_binding_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_token_binding_srv_conf_t  *prev = parent;
    ngx_http_token_binding_srv_conf_t  *conf = child;

    ngx_http_ssl_srv_conf_t  *sscf;

    if (conf->enabled == NGX_CONF_UNSET) {
        if (prev->enabled == NGX_CONF_UNSET) {
            conf->enabled = 0;

        } else {
            conf->enabled = prev->enabled;

            conf->enabled_conf_file = prev->enabled_conf_file;
            conf->enabled_conf_line = prev->enabled_conf_line;
        }
    }

    ngx_conf_merge_str_value(conf->cookies_secret, prev->cookies_secret, "");

    if (conf->cookies == NGX_CONF_UNSET_PTR) {
        if (conf->cookies_all == NGX_CONF_UNSET) {
            ngx_conf_merge_value(conf->cookies_all, prev->cookies_all, 0);
            ngx_conf_merge_ptr_value(conf->cookies, prev->cookies, NULL);

            conf->cookies_conf_file = prev->cookies_conf_file;
            conf->cookies_conf_line = prev->cookies_conf_line;

        } else {
            conf->cookies = NULL;
        }

    } else {
        conf->cookies_all = 0;
    }

    if (conf->cookies_all || conf->cookies) {

        if (conf->cookies_secret.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "\"token_binding_secret\" must be used to configure"
                          " secret key for \"token_binding_cookie\" directive"
                          " in %s:%ui",
                          conf->cookies_conf_file, conf->cookies_conf_line);

            return NGX_CONF_ERROR;
        }

        if (!conf->enabled) {
             conf->enabled = 1;
             conf->enabled_conf_file = conf->cookies_conf_file;
             conf->enabled_conf_line = conf->cookies_conf_line;
        }
    }

    if (conf->enabled) {
        sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

        if (sscf && sscf->ssl.ctx) {
            if (ngx_token_binding_enable(cf, &sscf->ssl) != NGX_OK) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "failed to enable Token Binding in %s:%ui",
                              conf->enabled_conf_file, conf->enabled_conf_line);

                return NGX_CONF_ERROR;
            }

        } else {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "failed to enable Token Binding in a server block"
                          " configured without SSL/TLS in %s:%ui",
                          conf->enabled_conf_file, conf->enabled_conf_line);

            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_token_binding_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_token_binding_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_token_binding_filter;

    return NGX_OK;
}


static char *
ngx_http_token_binding_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_token_binding_srv_conf_t  *tbscf = conf;

    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    tbscf->enabled_conf_file = cf->conf_file->file.name.data;
    tbscf->enabled_conf_line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static char *
ngx_http_token_binding_cookie(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_token_binding_srv_conf_t  *tbscf = conf;

    ngx_str_t  *value, *cookie;

    if (tbscf->cookies_all != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "all") == 0) {
        tbscf->cookies_all = 1;
        goto done;

    } else if (ngx_strcmp(value[1].data, "none") == 0) {
        tbscf->cookies_all = 0;
        goto done;
    }

    if (tbscf->cookies == NGX_CONF_UNSET_PTR) {
        tbscf->cookies = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (tbscf->cookies == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cookie = ngx_array_push(tbscf->cookies);
    if (cookie == NULL) {
        return NGX_CONF_ERROR;
    }

    *cookie = value[1];

done:

    if (tbscf->cookies_conf_file == NULL) {
        tbscf->cookies_conf_file = cf->conf_file->file.name.data;
        tbscf->cookies_conf_line = cf->conf_file->line;
    }

    return NGX_CONF_OK;
}
