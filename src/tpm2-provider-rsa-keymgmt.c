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

#include <tss2/tss2_mu.h>

#include "tpm2-provider-pkey.h"

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
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_HANDLE parentHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    size_t bits;
    BIGNUM *e;
};

static void *
tpm2_rsa_keymgmt_gen_init(void *provctx, int selection)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSAGEN_CTX *gen = OPENSSL_zalloc(sizeof(TPM2_RSAGEN_CTX));

    DBG("KEY GEN INIT\n");
    if (gen == NULL)
        return NULL;

    gen->core = cprov->core;
    gen->esys_ctx = cprov->esys_ctx;
    return gen;
}

#define TPM2_PKEY_PARAM_USER_AUTH "user-auth"

static int
tpm2_rsa_keymgmt_gen_set_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_RSAGEN_CTX *gen = ctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_USER_AUTH);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
                || p->data_size > sizeof(TPMU_HA))
            return 0;

        gen->inSensitive.sensitive.userAuth.size = p->data_size;
        memcpy(&gen->inSensitive.sensitive.userAuth.buffer, p->data,
               p->data_size);
    }

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
        OSSL_PARAM_utf8_string(TPM2_PKEY_PARAM_USER_AUTH, NULL, 0),
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
    TPM2_PKEY *pkey = NULL;
    TSS2_RC r = TSS2_RC_SUCCESS;

    DBG("KEY GEN%s %i bits\n",
        gen->inSensitive.sensitive.userAuth.size > 0 ? " with user-auth" : "",
        gen->bits);
    pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY));
    if (pkey == NULL) {
        TPM2_ERROR_raise(gen, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    pkey->core = gen->core;
    pkey->esys_ctx = gen->esys_ctx;

    inPublic.publicArea.parameters.rsaDetail.keyBits = gen->bits;
    if (gen->e)
        inPublic.publicArea.parameters.rsaDetail.exponent = BN_get_word(gen->e);

    if (gen->inSensitive.sensitive.userAuth.size == 0)
        pkey->data.emptyAuth = 1;

    r = init_tpm_parent(pkey, gen->parentHandle, &parent);
    TPM2_CHECK_RC(gen, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    pkey->data.parent = gen->parentHandle;

    size_t offset = 0;
    TPM2B_TEMPLATE template = { .size = 0 };
    r = Tss2_MU_TPMT_PUBLIC_Marshal(&inPublic.publicArea,
                                    template.buffer, sizeof(TPMT_PUBLIC), &offset);
    TPM2_CHECK_RC(gen, r, TPM2TSS_R_GENERAL_FAILURE, goto error);
    template.size = offset;

    r = Esys_CreateLoaded(gen->esys_ctx, parent,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &gen->inSensitive, &template,
                          &pkey->object, &keyPrivate, &keyPublic);
    TPM2_CHECK_RC(gen, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    pkey->data.pub = *keyPublic;
    pkey->data.priv = *keyPrivate;

    goto end;
 error:
    r = -1;
    if (pkey)
        OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
 end:
    free(keyPrivate);
    free(keyPublic);

    if (parent != ESYS_TR_NONE && !gen->parentHandle)
        Esys_FlushContext(gen->esys_ctx, parent);

    if (r == TSS2_RC_SUCCESS)
        return pkey;
    else
        return NULL;
}

static void
tpm2_rsa_keymgmt_gen_cleanup(void *ctx)
{
    TPM2_RSAGEN_CTX *gen = ctx;

    DBG("KEY CLEANUP\n");
    OPENSSL_clear_free(gen, sizeof(TPM2_RSAGEN_CTX));
}

static void *
tpm2_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    TPM2_PKEY *pkey = NULL;
    ESYS_TR parent = ESYS_TR_NONE;
    TSS2_RC r = 0;

    DBG("KEY LOAD\n");
    if (reference_sz != sizeof(pkey))
        return NULL;

    /* the contents of the reference is the address to our object */
    pkey = *(TPM2_PKEY **)reference;
    /* we grabbed it, so we detach it */
    *(TPM2_PKEY **)reference = NULL;

    if (pkey->object != ESYS_TR_NONE) {
        /* the object is already loaded, e.g. from the handle store */
        return pkey;
    }

    if (pkey->data.privatetype == KEY_TYPE_HANDLE) {
        r = Esys_TR_FromTPMPublic(pkey->esys_ctx, pkey->data.handle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &pkey->object);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);
    } else if (pkey->data.privatetype == KEY_TYPE_BLOB
               && pkey->data.parent != TPM2_RH_OWNER) {
        r = init_tpm_parent(pkey, pkey->data.parent, &parent);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

        DBG("Loading key blob wth custom parent.\n");
        r = Esys_Load(pkey->esys_ctx, parent,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      &pkey->data.priv, &pkey->data.pub, &pkey->object);
        Esys_TR_Close(pkey->esys_ctx, &parent);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);
    } else if (pkey->data.privatetype == KEY_TYPE_BLOB) {
        r = init_tpm_parent(pkey, 0, &parent);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

        DBG("Loading key blob.\n");
        r = Esys_Load(pkey->esys_ctx, parent,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      &pkey->data.priv, &pkey->data.pub, &pkey->object);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

        r = Esys_FlushContext(pkey->esys_ctx, parent);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);
        parent = ESYS_TR_NONE;
    } else {
        TPM2_ERROR_raise(pkey, TPM2TSS_R_TPM2DATA_READ_FAILED);
        return NULL;
    }

    r = Esys_TR_SetAuth(pkey->esys_ctx, pkey->object, &pkey->userauth);
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    return pkey;
 error:
    if (parent != ESYS_TR_NONE)
        Esys_FlushContext(pkey->esys_ctx, parent);

    if (pkey->object != ESYS_TR_NONE)
        Esys_FlushContext(pkey->esys_ctx, pkey->object);

    pkey->object = ESYS_TR_NONE;
    return NULL;
}


static void
tpm2_rsa_keymgmt_free(void *keydata)
{
    TPM2_PKEY *pkey = keydata;

    DBG("KEY FREE\n");
    if (pkey->object != ESYS_TR_NONE) {
        if (pkey->data.privatetype == KEY_TYPE_HANDLE)
            Esys_TR_Close(pkey->esys_ctx, &pkey->object);
        else
            Esys_FlushContext(pkey->esys_ctx, pkey->object);
    }

    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
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
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    OSSL_PARAM *p;

    DBG("KEY GET_PARAMS\n");
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, TPM2_MAX_RSA_KEY_BYTES))
        return 0;
    /* public key */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    if (p != NULL && !ossl_param_set_BN_from_buffer(p,
                          pkey->data.pub.publicArea.unique.rsa.buffer,
                          pkey->data.pub.publicArea.unique.rsa.size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL && !ossl_param_set_BN_from_uint32(p,
                          pkey->data.pub.publicArea.parameters.rsaDetail.exponent))
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
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    int ok = 0;

    DBG("KEY HAS\n");
    if (pkey != NULL) {
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
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    UINT32 exponent;
    int ok = 1;

    DBG("KEY EXPORT\n");
    if (pkey == NULL)
        return 0;

    OSSL_PARAM params[3];
#if defined(WORDS_BIGENDIAN)
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                        pkey->data.pub.publicArea.unique.rsa.buffer,
                                        pkey->data.pub.publicArea.unique.rsa.size);
#else
    unsigned char *n = OPENSSL_malloc(pkey->data.pub.publicArea.unique.rsa.size);
    /* just reverse the bytes; the BN export/import is unnecessarily complex */
    revmemcpy(n, pkey->data.pub.publicArea.unique.rsa.buffer,
                 pkey->data.pub.publicArea.unique.rsa.size);
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                        n, pkey->data.pub.publicArea.unique.rsa.size);
#endif
    exponent = pkey->data.pub.publicArea.parameters.rsaDetail.exponent;
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

