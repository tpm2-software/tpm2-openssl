/*******************************************************************************
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_rsa_encoder_ctx_st TPM2_RSA_ENCODER_CTX;

struct tpm2_rsa_encoder_ctx_st {
    TPM2_PROVIDER_CTX *prov_ctx;
};

static void *
key2text_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_ENCODER_CTX *ectx = OPENSSL_zalloc(sizeof(TPM2_RSA_ENCODER_CTX));

    if (ectx == NULL)
        return NULL;

    ectx->prov_ctx = cprov;
    return ectx;
}

static void
key2text_freectx(void *ctx)
{
    TPM2_RSA_ENCODER_CTX *ectx = ctx;

    OPENSSL_clear_free(ectx, sizeof(TPM2_RSA_ENCODER_CTX));
}

static const OSSL_PARAM *
key2text_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int
key2text_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    printf("key2text_get_params\n");

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pem"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pkcs8"))
        return 0;

    return 1;
}

static int
key2text_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key,
                const OSSL_PARAM key_abstract[], int selection,
                OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    TPM2_RSA_ENCODER_CTX *ectx = ctx;
    TPM2_DATA *tpm2Data = (TPM2_DATA *)key;
    BIO *out;
    int ret;

    printf("ENCODE\n");

    out = bio_new_from_core_bio(ectx->prov_ctx->corebiometh, cout);
    if (out == NULL)
        return 0;

    ret = tpm2_tpm2data_write(ectx->prov_ctx, tpm2Data, out);

    BIO_free(out);
    return ret;
}

const OSSL_DISPATCH tpm2_rsa_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))key2text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))key2text_freectx },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))key2text_gettable_params },
    { OSSL_FUNC_ENCODER_GET_PARAMS, (void (*)(void))key2text_get_params },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))key2text_encode },
    { 0, NULL }
};

