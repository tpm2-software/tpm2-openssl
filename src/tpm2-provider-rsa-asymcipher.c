/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_rsa_asymcipher_ctx_st TPM2_RSA_ASYMCIPHER_CTX;

struct tpm2_rsa_asymcipher_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_PKEY *pkey;
    TPM2B_PUBLIC_KEY_RSA *message;
};

static void
*rsa_asymcipher_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_ASYMCIPHER_CTX *actx = OPENSSL_zalloc(sizeof(TPM2_RSA_ASYMCIPHER_CTX));

    if (actx == NULL)
        return NULL;

    actx->core = cprov->core;
    actx->esys_ctx = cprov->esys_ctx;
    return actx;
}

static int
rsa_asymcipher_decrypt_init(void *ctx, void *provkey)
{
    TSS2_RC r;
    TPM2_RSA_ASYMCIPHER_CTX *actx = ctx;

    DBG("DECRYPT INIT\n");
    actx->pkey = provkey;

    return 1;
}

static int
decrypt_message(TPM2_RSA_ASYMCIPHER_CTX *actx,
                const unsigned char *in, size_t inlen)
{
    TSS2_RC r;
    TPM2B_PUBLIC_KEY_RSA cipher;
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label = { .size = 0 };

    if (inlen > (int)sizeof(cipher.buffer))
        return 0;

    cipher.size = inlen;
    memcpy(cipher.buffer, in, inlen);

    inScheme.scheme = TPM2_ALG_RSAES;

    r = Esys_RSA_Decrypt(actx->esys_ctx, actx->pkey->object,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &cipher, &inScheme, &label, &actx->message);
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
    TRACE_PARAMS("DECRYPT SET_CTX_PARAMS", params);

    return 1;
}

static const OSSL_PARAM *
rsa_asymcipher_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
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

