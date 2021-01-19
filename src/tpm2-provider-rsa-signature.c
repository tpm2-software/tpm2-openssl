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

typedef struct tpm2_rsa_signature_ctx_st TPM2_RSA_SIGNATURE_CTX;

struct tpm2_rsa_signature_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_PKEY *pkey;
    TPMT_SIG_SCHEME signScheme;
    ESYS_TR sequenceHandle;
    TPMT_SIGNATURE *signature;
};

static void *
rsa_signature_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_SIGNATURE_CTX *sctx = OPENSSL_zalloc(sizeof(TPM2_RSA_SIGNATURE_CTX));

    if (sctx == NULL)
        return NULL;

    sctx->core = cprov->core;
    sctx->esys_ctx = cprov->esys_ctx;
    sctx->signScheme.scheme = TPM2_ALG_NULL;
    sctx->signScheme.details.any.hashAlg = TPM2_ALG_NULL;
    return sctx;
}

static void
rsa_signature_freectx(void *ctx)
{
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;

    free(sctx->signature);
    OPENSSL_clear_free(sctx, sizeof(TPM2_RSA_SIGNATURE_CTX));
}

static int
rsa_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey)
{
    TSS2_RC r;
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;
    TPM2B_AUTH null_auth = { .size = 0 };

    DBG("SIGN INIT MD=%s\n", mdname);
    sctx->pkey = provkey;

    r = Esys_HashSequenceStart(sctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &null_auth, TPM2_ALG_SHA256, &sctx->sequenceHandle);
    TPM2_CHECK_RC(sctx, r, TPM2TSS_R_GENERAL_FAILURE, return 0);

    return 1;
}

static int
rsa_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen)
{
    TSS2_RC r;
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;
    TPM2B_MAX_BUFFER buf;

    DBG("SIGN UPDATE\n");
    if (datalen > TPM2_MAX_DIGEST_BUFFER)
        return 0;

    buf.size = datalen;
    memcpy(buf.buffer, data, datalen);

    r = Esys_SequenceUpdate(sctx->esys_ctx, sctx->sequenceHandle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &buf);
    TPM2_CHECK_RC(sctx, r, TPM2TSS_R_GENERAL_FAILURE, return 0);

    return 1;
}

static int
digest_sign_calculate(TPM2_RSA_SIGNATURE_CTX *sctx)
{
    TSS2_RC r;
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    DBG("SIGN CALCULATE\n");
    r = Esys_SequenceComplete(sctx->esys_ctx, sctx->sequenceHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL, ESYS_TR_RH_OWNER, &digest, &validation);
    TPM2_CHECK_RC(sctx, r, TPM2TSS_R_GENERAL_FAILURE, return 0);

    r = Esys_Sign(sctx->esys_ctx, sctx->pkey->object,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  digest, &sctx->signScheme, validation, &sctx->signature);
    free(digest);
    free(validation);
    TPM2_CHECK_RC(sctx, r, TPM2TSS_R_GENERAL_FAILURE, return 0);

    return 1;
}

static int
rsa_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;

    DBG("SIGN FINAL\n");
    if (!sctx->signature && !digest_sign_calculate(sctx))
        return 0;

    if (sctx->signature->sigAlg == TPM2_ALG_RSASSA) {
        *siglen = sctx->signature->signature.rsassa.sig.size;
        if (sig != NULL) {
            if (*siglen > sigsize)
                return 0;
            memcpy(sig, sctx->signature->signature.rsassa.sig.buffer, *siglen);
        }
    }

    return 1;
}

static int
rsa_signature_set_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;
    const OSSL_PARAM *p;

    DBG("SIGN SET_PARAMS\n");
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        if (strcmp(p->data, "pkcs1") == 0)
            sctx->signScheme.scheme = TPM2_ALG_RSASSA;
        else
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        if (strcmp(p->data, "sha256") == 0)
            sctx->signScheme.details.any.hashAlg = TPM2_ALG_SHA256;
        else
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *
rsa_signature_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };

    DBG("SIGN SETTABLE_PARAMS\n");
    return settable;
}

const OSSL_DISPATCH tpm2_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))rsa_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))rsa_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))rsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))rsa_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))rsa_signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void(*)(void))rsa_signature_set_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void(*)(void))rsa_signature_settable_params },
    { 0, NULL }
};

