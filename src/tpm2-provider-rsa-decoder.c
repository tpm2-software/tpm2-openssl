/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_rsa_decoder_ctx_st TPM2_RSA_DECODER_CTX;

struct tpm2_rsa_decoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    BIO_METHOD *corebiometh;
    ESYS_CONTEXT *esys_ctx;
    TPM2B_DIGEST parentAuth;
};

static void *
tpm2_decoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_DECODER_CTX *dctx = OPENSSL_zalloc(sizeof(TPM2_RSA_DECODER_CTX));

    if (dctx == NULL)
        return NULL;

    dctx->core = cprov->core;
    dctx->corebiometh = cprov->corebiometh;
    dctx->esys_ctx = cprov->esys_ctx;
    return dctx;
}

static void
tpm2_decoder_freectx(void *ctx)
{
    TPM2_RSA_DECODER_CTX *dctx = ctx;

    OPENSSL_clear_free(dctx, sizeof(TPM2_RSA_DECODER_CTX));
}

static const
OSSL_PARAM *tpm2_decoder_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DECODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int
tpm2_decoder_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    TRACE_PARAMS("DECODER GET_PARAMS", params);
    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "der"))
        return 0;

    return 1;
}

static int
tpm2_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
                OSSL_CALLBACK *object_cb, void *object_cbarg,
                OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_RSA_DECODER_CTX *dctx = ctx;
    TPM2_PKEY *pkey;
    BIO *bin;
    OSSL_PARAM params[4];
    int object_type, res;
    TSS2_RC r = 0;

    DBG("DECODER DECODE\n");
    if ((pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY))) == NULL)
        return 0;

    if ((bin = bio_new_from_core_bio(dctx->corebiometh, cin)) == NULL)
        goto error1;

    pkey->core = dctx->core;
    pkey->esys_ctx = dctx->esys_ctx;
    pkey->object = ESYS_TR_NONE;

    res = tpm2_keydata_read(bin, &pkey->data);
    BIO_free(bin);
    if (!res)
        goto error1;

    if (pkey->data.privatetype == KEY_TYPE_BLOB) {
        ESYS_TR parent = ESYS_TR_NONE;

        if (pkey->data.parent && pkey->data.parent != TPM2_RH_OWNER) {
            DBG("STORE/FILE LOAD parent: persistent 0x%x\n", pkey->data.parent);
            if (!tpm2_load_parent(pkey, pkey->data.parent, &dctx->parentAuth, &parent))
                goto error1;
        } else {
            DBG("STORE/FILE LOAD parent: primary 0x%x\n", TPM2_RH_OWNER);
            if (!tpm2_build_primary(pkey, ESYS_TR_RH_OWNER, &dctx->parentAuth, &parent))
                goto error1;
        }

        r = Esys_Load(pkey->esys_ctx, parent,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      &pkey->data.priv, &pkey->data.pub, &pkey->object);

        if (pkey->data.parent && pkey->data.parent != TPM2_RH_OWNER)
            Esys_TR_Close(pkey->esys_ctx, &parent);
        else
            Esys_FlushContext(pkey->esys_ctx, parent);

        TPM2_CHECK_RC(pkey, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error1);
    } else if (pkey->data.privatetype == KEY_TYPE_HANDLE) {
        r = Esys_TR_FromTPMPublic(pkey->esys_ctx, pkey->data.handle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &pkey->object);
        TPM2_CHECK_RC(pkey, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error1);
    } else {
        TPM2_ERROR_raise(pkey, TPM2_ERR_INPUT_CORRUPTED);
        goto error1;
    }

    if (!pkey->data.emptyAuth) {
        TPM2B_DIGEST userauth;
        size_t plen = 0;

        /* request password; this might open an interactive user prompt */
        if (!pw_cb(userauth.buffer, sizeof(TPMU_HA), &plen, NULL, pw_cbarg)) {
            TPM2_ERROR_raise(dctx, TPM2_ERR_AUTHORIZATION_FAILURE);
            goto error2;
        }
        userauth.size = plen;

        r = Esys_TR_SetAuth(dctx->esys_ctx, pkey->object, &userauth);
        TPM2_CHECK_RC(dctx, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error2);
    }

    /* submit the loaded key */
    object_type = OSSL_OBJECT_PKEY;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

    if (pkey->data.pub.publicArea.type == TPM2_ALG_RSA)
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     "RSA", 0);
    else {
        TPM2_ERROR_raise(dctx, TPM2_ERR_UNKNOWN_ALGORITHM);
        goto error2;
    }

    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &pkey, sizeof(pkey));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
error2:
    if (pkey->data.privatetype == KEY_TYPE_HANDLE)
        Esys_TR_Close(pkey->esys_ctx, &pkey->object);
    else
        Esys_FlushContext(pkey->esys_ctx, pkey->object);
error1:
    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
    return 0;
}

const OSSL_DISPATCH tpm2_rsa_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_decoder_freectx },
    { OSSL_FUNC_DECODER_GETTABLE_PARAMS, (void (*)(void))tpm2_decoder_gettable_params },
    { OSSL_FUNC_DECODER_GET_PARAMS, (void (*)(void))tpm2_decoder_get_params },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_decoder_decode },
    { 0, NULL }
};

