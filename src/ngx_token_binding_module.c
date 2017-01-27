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
#include <ngx_token_binding_module.h>

#include <token_bind_common.h>
#include <token_bind_server.h>


static void ngx_token_binding_cache_destroy(void *parent, void *ptr,
    CRYPTO_EX_DATA *ad, int index, long argl, void *argp);


static ngx_core_module_t  ngx_token_binding_module_ctx = {
    ngx_string("token_binding"),
    NULL,
    NULL
};


ngx_module_t  ngx_token_binding_module = {
    NGX_MODULE_V1,
    &ngx_token_binding_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static int  ngx_token_binding_cache_index;


ngx_int_t
ngx_token_binding_enable(ngx_conf_t *cf, ngx_ssl_t *ssl)
{
    if (!tbEnableTLSTokenBindingNegotiation(ssl->ctx)) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_token_binding_negotiated(ngx_connection_t *c)
{
    if (c->ssl == NULL || c->ssl->connection == NULL) {
        return NGX_DECLINED;
    }

    if (!tbTokenBindingEnabled(c->ssl->connection, NULL)) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


ngx_int_t
ngx_token_binding_verify(ngx_connection_t *c, ngx_str_t *message,
    ngx_str_t *provided, ngx_str_t *referred)
{
    tbCache         *cache;
    uint8_t          tls_ekm[TB_HASH_LEN];
    tbKeyType        tls_key_type;
    ngx_ssl_conn_t  *ssl_conn;

    if (c->ssl == NULL || c->ssl->connection == NULL) {
        return NGX_DECLINED;
    }

    ssl_conn = c->ssl->connection;

    if (!tbTokenBindingEnabled(ssl_conn, &tls_key_type)) {
        return NGX_DECLINED;
    }

    cache = SSL_get_ex_data(ssl_conn, ngx_token_binding_cache_index);

    if (cache == NULL) {

        cache = tbCacheCreate();

        if (cache == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "tbCacheCreate() failed");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "Token Binding cache created: %p", cache);

        if (SSL_set_ex_data(ssl_conn, ngx_token_binding_cache_index, cache)
            == 0)
        {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "SSL_set_ex_data() failed");
            return NGX_ERROR;
        }

    } else {

        if (tbCacheMessageAlreadyVerified(cache, message->data, message->len,
                                          &provided->data, &provided->len,
                                          &referred->data, &referred->len))
        {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                          "Token Binding message verified successfully"
                          " (from cache)");
            return NGX_OK;
        }
    }

    if (!tbGetEKM(ssl_conn, tls_ekm)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "tbGetEKM() failed");
        return NGX_ERROR;
    }

    if (tbCacheVerifyTokenBindingMessage(cache, message->data, message->len,
                                          tls_key_type, tls_ekm,
                                          &provided->data, &provided->len,
                                          &referred->data, &referred->len))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "Token Binding message verified successfully");
        return NGX_OK;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_token_binding_hash(ngx_str_t *id, ngx_str_t *out, ngx_pool_t *pool)
{
    u_char     tb_data[TB_HASH_LEN];
    ngx_str_t  tb_hash;

    out->data = ngx_pnalloc(pool, ngx_base64_encoded_length(TB_HASH_LEN));
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    tbHashTokenBindingID(id->data, id->len, tb_data);

    tb_hash.data = tb_data;
    tb_hash.len = TB_HASH_LEN;

    ngx_encode_base64url(out, &tb_hash);

    return NGX_OK;
}


void
ngx_token_binding_key_type(ngx_str_t *id, ngx_str_t *out)
{
    switch (tbGetKeyType(id->data, id->len)) {

    case TB_RSA2048_PKCS15:
        ngx_str_set(out, "rsa2048-pkcs1.5");
        break;

    case TB_RSA2048_PSS:
        ngx_str_set(out, "rsa2048-pss");
        break;

    case TB_ECDSAP256:
        ngx_str_set(out, "ecdsa-p256");
        break;

    case TB_INVALID_KEY_TYPE:
        ngx_str_set(out, "invalid");
        break;

    default:
        ngx_str_set(out, "unknown");
    }
}


ngx_int_t
ngx_token_binding_calculate_hmac(ngx_str_t *key, ngx_array_t *data,
    ngx_str_t *hmac, ngx_pool_t *pool)
{
    u_char         hash[SHA256_DIGEST_LENGTH];
    HMAC_CTX      *hctx;
    ngx_str_t     *in, binary;
    ngx_uint_t     i;
    unsigned int   len;

#if OPENSSL_VERSION_NUMBER >= 0x10100001L

    hctx = HMAC_CTX_new();
    if (hctx == NULL) {
        return NGX_ERROR;
    }

#else

    hctx = ngx_palloc(pool, sizeof(HMAC_CTX));
    if (hctx == NULL) {
        return NGX_ERROR;
    }

    HMAC_CTX_init(hctx);

#endif

    if (HMAC_Init_ex(hctx, key->data, key->len, EVP_sha256(), NULL) != 1) {
        ngx_ssl_error(NGX_LOG_ALERT, pool->log, 0,
                      "HMAC_Init_ex() failed");
        goto failed;
    }

    in = data->elts;

    for (i = 0; i < data->nelts; i++) {
        if (!HMAC_Update(hctx, in[i].data, in[i].len)) {
            ngx_ssl_error(NGX_LOG_ALERT, pool->log, 0,
                          "HMAC_Update() failed");
            goto failed;
        }
    }

    if (!HMAC_Final(hctx, hash, &len)) {
        ngx_ssl_error(NGX_LOG_ALERT, pool->log, 0,
                      "HMAC_Final() failed");
        goto failed;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100001L
    HMAC_CTX_free(hctx);
#else
    HMAC_CTX_cleanup(hctx);
#endif

    hmac->data = ngx_pnalloc(pool, ngx_base64_encoded_length(len));
    if (hmac->data == NULL) {
        return NGX_ERROR;
    }

    binary.data = hash;
    binary.len = len;

    ngx_encode_base64url(hmac, &binary);

    return NGX_OK;

failed:

#if OPENSSL_VERSION_NUMBER >= 0x10100001L
    HMAC_CTX_free(hctx);
#else
    HMAC_CTX_cleanup(hctx);
#endif

    return NGX_ERROR;
}


static void
ngx_token_binding_cache_destroy(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int index, long argl, void *argp)
{
#if (NGX_DEBUG)
    ngx_connection_t  *c;
#endif

    if (ptr) {
#if (NGX_DEBUG)
        c = ngx_ssl_get_connection(parent);
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "Token Binding cache destroyed: %p", ptr);
#endif
        tbCacheDestroy(ptr);
    }
}


ngx_int_t
ngx_token_binding_init(ngx_conf_t *cf)
{
    uint64_t  nonce;

    ngx_token_binding_cache_index = SSL_get_ex_new_index(0, NULL, NULL, NULL,
                                               ngx_token_binding_cache_destroy);
    if (ngx_token_binding_cache_index == -1) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    if (!tbTLSLibInit()) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "tbTLSLibInit() failed");
        return NGX_ERROR;
    }

    do {
        nonce = (uint64_t) ngx_random();
    } while (nonce == 0);

    tbCacheLibInit(nonce);

    return NGX_OK;
}
