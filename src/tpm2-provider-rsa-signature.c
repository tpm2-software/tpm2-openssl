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
    TPM2_PROVIDER_CTX *prov_ctx;
    TPM2_DATA *tpm2Data;
    ESYS_TR keyObject;
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

    sctx->prov_ctx = cprov;
    return sctx;
}

static void
rsa_signature_freectx(void *ctx)
{
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;

    if (sctx->keyObject != ESYS_TR_NONE) {
        if (sctx->tpm2Data->privatetype == KEY_TYPE_HANDLE)
            Esys_TR_Close(sctx->prov_ctx->esys_ctx, &sctx->keyObject);
        else
            Esys_FlushContext(sctx->prov_ctx->esys_ctx, sctx->keyObject);
    }

    free(sctx->signature);
    OPENSSL_clear_free(sctx, sizeof(TPM2_RSA_SIGNATURE_CTX));
}

static int
rsa_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey)
{
    TSS2_RC r;
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;
    TPM2B_AUTH null_auth = { .size = 0 };

    printf("SIGN INIT\n");
    sctx->tpm2Data = provkey;

    r = tpm2_init_key(sctx->prov_ctx, sctx->tpm2Data, &sctx->keyObject);
    if (r != TSS2_RC_SUCCESS)
        return 0;

    r = Esys_HashSequenceStart(sctx->prov_ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &null_auth, TPM2_ALG_SHA256, &sctx->sequenceHandle);
    if (r != TSS2_RC_SUCCESS)
        return 0;

    return 1;
}

static int
rsa_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen)
{
    TSS2_RC r;
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;
    TPM2B_MAX_BUFFER buf;

    printf("SIGN UPDATE\n");

    if (datalen > TPM2_MAX_DIGEST_BUFFER)
        return 0;

    buf.size = datalen;
    memcpy(buf.buffer, data, datalen);

    r = Esys_SequenceUpdate(sctx->prov_ctx->esys_ctx, sctx->sequenceHandle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &buf);

    if (r != TSS2_RC_SUCCESS)
        return 0;

    return 1;
}

static int
digest_sign_calculate(TPM2_RSA_SIGNATURE_CTX *sctx)
{
    TSS2_RC r;
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL, .details.any.hashAlg = TPM2_ALG_SHA256 };

    printf("SIGN CALCULATE\n");

    r = Esys_SequenceComplete(sctx->prov_ctx->esys_ctx, sctx->sequenceHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL, ESYS_TR_RH_OWNER, &digest, &validation);

    if (r != TSS2_RC_SUCCESS)
        return 0;

    r = Esys_Sign(sctx->prov_ctx->esys_ctx, sctx->keyObject,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  digest, &inScheme, validation, &sctx->signature);
    free(digest);
    free(validation);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("%s\n", Tss2_RC_Decode(r));
        return 0;
    }

    return 1;
}

static int
rsa_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    TPM2_RSA_SIGNATURE_CTX *sctx = ctx;

    printf("SIGN FINAL\n");
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

const OSSL_DISPATCH tpm2_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))rsa_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))rsa_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))rsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))rsa_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))rsa_signature_digest_sign_final },
    { 0, NULL }
};

