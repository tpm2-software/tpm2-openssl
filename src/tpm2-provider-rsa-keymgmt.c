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

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

static TPM2B_DATA allOutsideInfo = {
    .size = 0,
};

static TPML_PCR_SELECTION allCreationPCR = {
    .count = 0,
};

static TPM2B_PUBLIC keyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_NODA),
        .authPolicy.size = 0,
        .parameters.rsaDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .keyBits = 0,          /* to be set by the genkey function */
             .exponent = 0,         /* to be set by the genkey function */
         },
        .unique.rsa.size = 0
     }
};

typedef struct tpm2_rsagen_ctx_st TPM2_RSAGEN_CTX;

struct tpm2_rsagen_ctx_st {
    TPM2_PROVIDER_CTX *prov_ctx;
    TPM2_HANDLE parentHandle;
    char *password;
    size_t bits;
    BIGNUM *e;
};

static void *
tpm2_rsa_keymgmt_gen_init(void *provctx, int selection)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSAGEN_CTX *gen = OPENSSL_zalloc(sizeof(TPM2_RSAGEN_CTX));

    if (gen == NULL)
        return NULL;

    gen->prov_ctx = cprov;
    return gen;
}

static int
tpm2_rsa_keymgmt_gen_set_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_RSAGEN_CTX *gen = ctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &gen->bits))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL && !OSSL_PARAM_get_BN(p, &gen->e))
        return 0;

    return 1;
}

static const OSSL_PARAM *
tpm2_rsa_keymgmt_gen_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static void *
tpm2_rsa_keymgmt_gen(void *ctx, OSSL_CALLBACK *cb, void *cbarg)
{
    TPM2_RSAGEN_CTX *gen = ctx;
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC inPublic = keyTemplate;
    TPM2B_PUBLIC *keyPublic = NULL;
    TPM2B_PRIVATE *keyPrivate = NULL;
    TPM2_DATA *tpm2Data = NULL;
    TSS2_RC r = TSS2_RC_SUCCESS;
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .sensitive = {
            .userAuth = {
                 .size = 0,
             },
            .data = {
                 .size = 0,
             }
        }
    };

    tpm2Data = OPENSSL_zalloc(sizeof(TPM2_DATA));
    if (tpm2Data == NULL) {
        TPM2_ERROR_raise(gen->prov_ctx, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    inPublic.publicArea.parameters.rsaDetail.keyBits = gen->bits;
    if (gen->e)
        inPublic.publicArea.parameters.rsaDetail.exponent = BN_get_word(gen->e);

    if (gen->password) {
        DBG("Setting a password for the created key.\n");
        if (strlen(gen->password) > sizeof(tpm2Data->userauth.buffer) - 1) {
            goto error;
        }
        tpm2Data->userauth.size = strlen(gen->password);
        memcpy(&tpm2Data->userauth.buffer[0], gen->password,
               tpm2Data->userauth.size);

        inSensitive.sensitive.userAuth.size = strlen(gen->password);
        memcpy(&inSensitive.sensitive.userAuth.buffer[0], gen->password,
               strlen(gen->password));
    } else
        tpm2Data->emptyAuth = 1;

    r = init_tpm_parent(gen->prov_ctx, gen->parentHandle, &parent);
    TPM2_CHECK_RC(gen->prov_ctx, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    tpm2Data->parent = gen->parentHandle;

    DBG("Generating RSA key for %i bits keysize.\n", gen->bits);

    r = Esys_Create(gen->prov_ctx->esys_ctx, parent,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive, &inPublic, &allOutsideInfo, &allCreationPCR,
                    &keyPrivate, &keyPublic, NULL, NULL, NULL);
    TPM2_CHECK_RC(gen->prov_ctx, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    DBG("Generated the RSA key inside the TPM.\n");

    tpm2Data->pub = *keyPublic;
    tpm2Data->priv = *keyPrivate;

    goto end;
 error:
    r = -1;
    if (tpm2Data)
        OPENSSL_free(tpm2Data);

 end:
    free(keyPrivate);
    free(keyPublic);

    if (parent != ESYS_TR_NONE && !gen->parentHandle)
        Esys_FlushContext(gen->prov_ctx->esys_ctx, parent);

    if (r == TSS2_RC_SUCCESS)
        return tpm2Data;
    else
        return NULL;
}

static void
tpm2_rsa_keymgmt_gen_cleanup(void *ctx)
{
    TPM2_RSAGEN_CTX *gen = ctx;

    OPENSSL_clear_free(gen, sizeof(TPM2_RSAGEN_CTX));
}

static void *
tpm2_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    TPM2_DATA *tpm2Data = NULL;

    if (reference_sz == sizeof(tpm2Data)) {
        /* The contents of the reference is the address to our object */
        tpm2Data = *(TPM2_DATA **)reference;

        return tpm2Data;
    }

    return NULL;
}

static void
tpm2_rsa_keymgmt_free(void *keydata)
{
    OPENSSL_clear_free(keydata, sizeof(TPM2_DATA));
}

static int
ossl_param_set_BN_from_buffer(OSSL_PARAM *p, const BYTE *buffer, UINT16 size)
{
    int res;
    BIGNUM *bignum = BN_bin2bn(buffer, size, NULL);

    res = OSSL_PARAM_set_BN(p, bignum);
    BN_free(bignum);
    return res;
}

static int
ossl_param_set_BN_from_uint32(OSSL_PARAM *p, UINT32 num)
{
    int res;
    BIGNUM *bignum = BN_new();

    BN_set_word(bignum, num);
    res = OSSL_PARAM_set_BN(p, bignum);
    BN_free(bignum);
    return res;
}

static int
tpm2_rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    TPM2_DATA *tpm2Data = (TPM2_DATA *)keydata;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, TPM2_MAX_RSA_KEY_BYTES))
        return 0;
    /* public key */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    if (p != NULL && !ossl_param_set_BN_from_buffer(p,
                          tpm2Data->pub.publicArea.unique.rsa.buffer,
                          tpm2Data->pub.publicArea.unique.rsa.size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL && !ossl_param_set_BN_from_uint32(p,
                          tpm2Data->pub.publicArea.parameters.rsaDetail.exponent))
        return 0;

    return 1;
}

static const OSSL_PARAM *
tpm2_rsa_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        /* public key */
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}

static int
tpm2_rsa_keymgmt_has(const void *keydata, int selection)
{
    TPM2_DATA *tpm2Data = (TPM2_DATA *)keydata;
    int ok = 0;

    if (tpm2Data != NULL) {
        /* we always have a full keypair,
           although the private portion is not exportable */
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
            ok = 1;
    }
    return ok;
}

static void *
revmemcpy(void *dest, const void *src, size_t len)
{
    char *d = dest + len - 1;
    const char *s = src;
    while (len--)
        *d-- = *s++;
    return dest;
}

static int
tpm2_rsa_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    TPM2_DATA *tpm2Data = (TPM2_DATA *)keydata;
    UINT32 exponent;
    int ok = 1;

    if (tpm2Data == NULL)
        return 0;

    printf("EXPORT\n");

    OSSL_PARAM params[3];
#if defined(WORDS_BIGENDIAN)
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                        tpm2Data->pub.publicArea.unique.rsa.buffer,
                                        tpm2Data->pub.publicArea.unique.rsa.size);
#else
    unsigned char *n = OPENSSL_malloc(tpm2Data->pub.publicArea.unique.rsa.size);
    /* just reverse the bytes; the BN export/import is unnecessarily complex */
    revmemcpy(n, tpm2Data->pub.publicArea.unique.rsa.buffer,
                 tpm2Data->pub.publicArea.unique.rsa.size);
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                        n, tpm2Data->pub.publicArea.unique.rsa.size);
#endif
    exponent = tpm2Data->pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                        (unsigned char *)&exponent, sizeof(exponent));
    params[2] = OSSL_PARAM_construct_end();

    ok = param_cb(params, cbarg);

#if !defined(WORDS_BIGENDIAN)
    OPENSSL_free(n);
#endif
    return ok;
}

static const OSSL_PARAM *
tpm2_rsa_keymgmt_export_types(int selection)
{
    static const OSSL_PARAM rsa_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return rsa_public_key_types;
    else
        return NULL;
}

const OSSL_DISPATCH tpm2_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void(*)(void))tpm2_rsa_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void(*)(void))tpm2_rsa_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void(*)(void))tpm2_rsa_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void(*)(void))tpm2_rsa_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void(*)(void))tpm2_rsa_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void(*)(void))tpm2_rsa_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void(*)(void))tpm2_rsa_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void(*)(void))tpm2_rsa_keymgmt_export_types },
    { 0, NULL }
};

