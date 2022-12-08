/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

#include "tpm2-provider-pkey.h"

#ifdef _MSC_VER 
//not #if defined(_WIN32) || defined(_WIN64) because we have strncasecmp in mingw
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

typedef struct tpm2_rsa_asymcipher_ctx_st TPM2_RSA_ASYMCIPHER_CTX;

struct tpm2_rsa_asymcipher_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPMT_RSA_DECRYPT decrypt;
    /* TLS padding */
    unsigned int client_version;
    unsigned int alt_version;
    TPM2_PKEY *pkey;
    TPM2B_PUBLIC_KEY_RSA *message;
};

static OSSL_FUNC_asym_cipher_newctx_fn rsa_asymcipher_newctx;
static OSSL_FUNC_asym_cipher_decrypt_init_fn rsa_asymcipher_decrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_fn rsa_asymcipher_decrypt;
static OSSL_FUNC_asym_cipher_freectx_fn rsa_asymcipher_freectx;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn rsa_asymcipher_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn rsa_asymcipher_settable_ctx_params;

static void
*rsa_asymcipher_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_ASYMCIPHER_CTX *actx = OPENSSL_zalloc(sizeof(TPM2_RSA_ASYMCIPHER_CTX));

    if (actx == NULL)
        return NULL;

    actx->core = cprov->core;
    actx->esys_ctx = cprov->esys_ctx;
    actx->decrypt.scheme = TPM2_ALG_RSAES;
    return actx;
}

static int
rsa_asymcipher_decrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    TPM2_RSA_ASYMCIPHER_CTX *actx = ctx;

    DBG("DECRYPT INIT\n");
    actx->pkey = provkey;

    return rsa_asymcipher_set_ctx_params(actx, params);
}

static int
decrypt_message(TPM2_RSA_ASYMCIPHER_CTX *actx,
                const unsigned char *in, size_t inlen)
{
    TSS2_RC r;
    TPM2B_PUBLIC_KEY_RSA cipher;
    TPM2B_DATA label = { .size = 0 };

    if (inlen > (int)sizeof(cipher.buffer))
        return 0;

    cipher.size = inlen;
    memcpy(cipher.buffer, in, inlen);

    r = Esys_RSA_Decrypt(actx->esys_ctx, actx->pkey->object,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &cipher, &actx->decrypt, &label, &actx->message);
    TPM2_CHECK_RC(actx->core, r, TPM2_ERR_CANNOT_DECRYPT, return 0);

    return 1;
}

static int
rsa_asymcipher_decrypt(void *ctx, unsigned char *out, size_t *outlen,
                       size_t outsize, const unsigned char *in, size_t inlen)
{
    TPM2_RSA_ASYMCIPHER_CTX *actx = ctx;

    DBG("DECRYPT\n");
    if (!actx->message && !decrypt_message(actx, in, inlen))
        return 0;

    *outlen = actx->message->size;
    if (out != NULL) {
        if (*outlen > outsize)
            return 0;
        memcpy(out, actx->message->buffer, *outlen);
    }

    return 1;
}

static void
rsa_asymcipher_freectx(void *ctx)
{
    TPM2_RSA_ASYMCIPHER_CTX *actx = ctx;

    if (actx == NULL)
        return;

    if (actx->message != NULL)
        free(actx->message);

    OPENSSL_clear_free(actx, sizeof(TPM2_RSA_ASYMCIPHER_CTX));
}

static int
rsa_asymcipher_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_RSA_ASYMCIPHER_CTX *actx = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("DECRYPT SET_CTX_PARAMS", params);

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        int pad_mode = 0;

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;

            if (pad_mode == RSA_PKCS1_PADDING
                    || pad_mode == RSA_PKCS1_WITH_TLS_PADDING)
                actx->decrypt.scheme = TPM2_ALG_RSAES;
            else
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (!strcasecmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15))
                actx->decrypt.scheme = TPM2_ALG_RSAES;
            else
                return 0;
            break;
        default:
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL) {
        unsigned int client_version;

        if (!OSSL_PARAM_get_uint(p, &client_version))
            return 0;
        actx->client_version = client_version;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL) {
        unsigned int alt_version;

        if (!OSSL_PARAM_get_uint(p, &alt_version))
            return 0;
        actx->alt_version = alt_version;
    }

    return 1;
}

static const OSSL_PARAM *
rsa_asymcipher_settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

const OSSL_DISPATCH tpm2_rsa_asymcipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))rsa_asymcipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))rsa_asymcipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))rsa_asymcipher_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))rsa_asymcipher_freectx },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))rsa_asymcipher_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))rsa_asymcipher_settable_ctx_params },
    { 0, NULL }
};

