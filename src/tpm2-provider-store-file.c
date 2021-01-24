/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_file_ctx_st TPM2_FILE_CTX;

struct tpm2_file_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    BIO *bin;
    TPM2B_DIGEST parentAuth;
};

static void *
tpm2_file_open(void *provctx, const char *uri)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_FILE_CTX *ctx = NULL;
    BIO *bio;

    DBG("STORE/FILE OPEN %s\n", uri);
    bio = BIO_new_file(uri, "r");
    if (!bio)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(TPM2_FILE_CTX));
    if (ctx == NULL) {
        BIO_free(bio);
        return NULL;
    }

    ctx->core = cprov->core;
    ctx->esys_ctx = cprov->esys_ctx;
    ctx->bin = bio;

    return ctx;
}

static void *
tpm2_file_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    DBG("STORE/FILE ATTACH\n");
    // attach operation is required, but not supported
    return NULL;
}

static const OSSL_PARAM *
tpm2_file_settable_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int
tpm2_file_set_params(void *loaderctx, const OSSL_PARAM params[])
{
    return 1;
}

static int
tpm2_file_load(void *ctx,
            OSSL_CALLBACK *object_cb, void *object_cbarg,
            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_FILE_CTX *fctx = ctx;
    TPM2_PKEY *pkey;
    OSSL_PARAM params[4];
    int object_type;
    int ret;
    TSS2_RC r = 0;

    DBG("STORE/FILE LOAD\n");
    pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY));
    if (pkey == NULL)
        return 0;

    pkey->core = fctx->core;
    pkey->esys_ctx = fctx->esys_ctx;
    pkey->object = ESYS_TR_NONE;

    ret = tpm2_keydata_read(fctx->bin, &pkey->data);
    if (ret == 0) {
        /* no more data */
        OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
        return 1;
    } else if (ret < 0)
        goto error1;

    if (pkey->data.privatetype == KEY_TYPE_BLOB) {
        ESYS_TR parent = ESYS_TR_NONE;

        if (pkey->data.parent && pkey->data.parent != TPM2_RH_OWNER) {
            DBG("STORE/FILE LOAD parent: persistent 0x%x\n", pkey->data.parent);
            if (!tpm2_load_parent(pkey, pkey->data.parent, &fctx->parentAuth, &parent))
                goto error1;
        } else {
            DBG("STORE/FILE LOAD parent: primary 0x%x\n", TPM2_RH_OWNER);
            if (!tpm2_build_primary(pkey, ESYS_TR_RH_OWNER, &fctx->parentAuth, &parent))
                goto error1;
        }

        r = Esys_Load(pkey->esys_ctx, parent,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      &pkey->data.priv, &pkey->data.pub, &pkey->object);

        if (pkey->data.parent && pkey->data.parent != TPM2_RH_OWNER)
            Esys_TR_Close(pkey->esys_ctx, &parent);
        else
            Esys_FlushContext(pkey->esys_ctx, parent);

        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error1);
    } else if (pkey->data.privatetype == KEY_TYPE_HANDLE) {
        r = Esys_TR_FromTPMPublic(pkey->esys_ctx, pkey->data.handle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &pkey->object);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error1);
    } else {
        TPM2_ERROR_raise(pkey, TPM2TSS_R_TPM2DATA_READ_FAILED);
        goto error1;
    }

    if (!pkey->data.emptyAuth) {
        TPM2B_DIGEST userauth;
        size_t plen = 0;

        /* request password; this might open an interactive user prompt */
        if (!pw_cb(userauth.buffer, sizeof(TPMU_HA), &plen, NULL, pw_cbarg)) {
            TPM2_ERROR_raise(fctx, TPM2TSS_R_GENERAL_FAILURE);
            goto error2;
        }
        userauth.size = plen;

        r = Esys_TR_SetAuth(fctx->esys_ctx, pkey->object, &userauth);
        TPM2_CHECK_RC(fctx, r, TPM2TSS_R_GENERAL_FAILURE, goto error2);
    }

    /* submit the loaded key */
    object_type = OSSL_OBJECT_PKEY;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

    if (pkey->data.pub.publicArea.type == TPM2_ALG_RSA)
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     "RSA", 0);
    else {
        TPM2_ERROR_raise(fctx, TPM2TSS_R_GENERAL_FAILURE);
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

static int
tpm2_file_eof(void *ctx)
{
    TPM2_FILE_CTX *fctx = ctx;

    return !BIO_pending(fctx->bin) && BIO_eof(fctx->bin);
}

static int
tpm2_file_close(void *ctx)
{
    TPM2_FILE_CTX *fctx = ctx;

    DBG("STORE/FILE CLOSE\n");

    BIO_free(fctx->bin);
    OPENSSL_clear_free(fctx, sizeof(TPM2_FILE_CTX));

    return 1;
}

const OSSL_DISPATCH tpm2_file_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))tpm2_file_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))tpm2_file_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_file_settable_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))tpm2_file_set_params },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))tpm2_file_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))tpm2_file_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))tpm2_file_close },
    { 0, NULL }
};

