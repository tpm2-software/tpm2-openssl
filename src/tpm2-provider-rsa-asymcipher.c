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

typedef struct tpm2_rsa_asymcipher_ctx_st TPM2_RSA_ASYMCIPHER_CTX;

struct tpm2_rsa_asymcipher_ctx_st {
    TPM2_PROVIDER_CTX *prov_ctx;
    TPM2_DATA *tpm2Data;
    ESYS_TR keyObject;
    TPM2B_PUBLIC_KEY_RSA *message;
};

static void
*rsa_asymcipher_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_ASYMCIPHER_CTX *actx = OPENSSL_zalloc(sizeof(TPM2_RSA_ASYMCIPHER_CTX));

    if (actx == NULL)
        return NULL;

    actx->prov_ctx = cprov;
    return actx;
}

static int
rsa_asymcipher_decrypt_init(void *ctx, void *provkey)
{
    TSS2_RC r;
    TPM2_RSA_ASYMCIPHER_CTX *actx = ctx;

    printf("DECRYPT INIT\n");
    actx->tpm2Data = provkey;

    r = tpm2_init_key(actx->prov_ctx, actx->tpm2Data, &actx->keyObject);
    if (r != TSS2_RC_SUCCESS)
        return 0;

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

    r = Esys_RSA_Decrypt(actx->prov_ctx->esys_ctx, actx->keyObject,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &cipher, &inScheme, &label, &actx->message);

    if (r != TSS2_RC_SUCCESS) {
        printf("%s\n", Tss2_RC_Decode(r));
        return 0;
    }

    return 1;
}

static int
rsa_asymcipher_decrypt(void *ctx, unsigned char *out, size_t *outlen,
                       size_t outsize, const unsigned char *in, size_t inlen)
{
    TPM2_RSA_ASYMCIPHER_CTX *actx = ctx;

    printf("DECRYPT\n");
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

    printf("ACIPHER FREECTX\n");

    if (actx->keyObject != ESYS_TR_NONE) {
        if (actx->tpm2Data->privatetype == KEY_TYPE_HANDLE)
            Esys_TR_Close(actx->prov_ctx->esys_ctx, &actx->keyObject);
        else
            Esys_FlushContext(actx->prov_ctx->esys_ctx, actx->keyObject);
    }

    free(actx->message);
    OPENSSL_clear_free(actx, sizeof(TPM2_RSA_ASYMCIPHER_CTX));
}

const OSSL_DISPATCH tpm2_rsa_asymcipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))rsa_asymcipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))rsa_asymcipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))rsa_asymcipher_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))rsa_asymcipher_freectx },
    { 0, NULL }
};

