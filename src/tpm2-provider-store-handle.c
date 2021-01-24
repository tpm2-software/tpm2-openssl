/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider.h"

typedef struct tpm2_handle_ctx_st TPM2_HANDLE_CTX;

struct tpm2_handle_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_HANDLE handle;
    int has_pass;
    int load_done;
};

static void *
tpm2_handle_open(void *provctx, const char *uri)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    unsigned long int value;
    char *end_ptr = NULL;
    TPM2_HANDLE_CTX *ctx = NULL;

    DBG("STORE/HANDLE OPEN %s\n", uri);
    ctx = OPENSSL_zalloc(sizeof(TPM2_HANDLE_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->core = cprov->core;
    ctx->esys_ctx = cprov->esys_ctx;

    if (!strncmp(uri, "handle:", 7))
    {
        value = strtoul(uri+7, &end_ptr, 16);
        if (*end_ptr == '?') {
            if (!strncmp(end_ptr+1, "pass", 4))
                ctx->has_pass = 1;
            else
                goto error;
        }
        else if (*end_ptr != 0 || value > UINT32_MAX)
            goto error;

        ctx->handle = value;
        return ctx;
    }
error:
    OPENSSL_clear_free(ctx, sizeof(TPM2_HANDLE_CTX));
    return NULL;
}

static void *
tpm2_handle_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    DBG("STORE/HANDLE ATTACH\n");
    // attach operation is required, but not supported
    return NULL;
}

static const OSSL_PARAM *
tpm2_handle_settable_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int
tpm2_handle_set_params(void *loaderctx, const OSSL_PARAM params[])
{
    return 1;
}

static int
tpm2_handle_load(void *ctx,
            OSSL_CALLBACK *object_cb, void *object_cbarg,
            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_HANDLE_CTX *csto = ctx;
    TPM2B_PUBLIC *out_public = NULL;
    TPM2_PKEY *pkey = NULL;
    TSS2_RC r;

    DBG("STORE/HANDLE LOAD\n");
    pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY));
    if (pkey == NULL)
        return 0;

    pkey->core = csto->core;
    pkey->esys_ctx = csto->esys_ctx;

    r = Esys_TR_FromTPMPublic(csto->esys_ctx, csto->handle,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &pkey->object);
    TPM2_CHECK_RC(csto, r, TPM2TSS_R_GENERAL_FAILURE, goto error1);

    if (csto->has_pass) {
        TPM2B_DIGEST userauth;
        size_t plen = 0;

        /* request password; this might open an interactive user prompt */
        if (!pw_cb(userauth.buffer, sizeof(TPMU_HA), &plen, NULL, pw_cbarg)) {
            TPM2_ERROR_raise(csto, TPM2TSS_R_GENERAL_FAILURE);
            goto error2;
        }
        userauth.size = plen;

        r = Esys_TR_SetAuth(csto->esys_ctx, pkey->object, &userauth);
        TPM2_CHECK_RC(csto, r, TPM2TSS_R_GENERAL_FAILURE, goto error2);
    } else
        pkey->data.emptyAuth = 1;

    r = Esys_ReadPublic(csto->esys_ctx, pkey->object,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &out_public, NULL, NULL);
    TPM2_CHECK_RC(csto, r, TPM2TSS_R_GENERAL_FAILURE, goto error2);

    pkey->data.pub = *out_public;
    pkey->data.privatetype = KEY_TYPE_HANDLE;
    pkey->data.handle = csto->handle;

    free(out_public);
    csto->load_done = 1;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

    if (pkey->data.pub.publicArea.type == TPM2_ALG_RSA)
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     "RSA", 0);
    else {
        TPM2_ERROR_raise(csto, TPM2TSS_R_GENERAL_FAILURE);
        goto error2;
    }

    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &pkey, sizeof(pkey));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
error2:
    Esys_TR_Close(csto->esys_ctx, &csto->handle);
error1:
    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
    return 0;
}

static int
tpm2_handle_eof(void *ctx)
{
    TPM2_HANDLE_CTX *csto = ctx;
    return csto->load_done;
}

static int
tpm2_handle_close(void *ctx)
{
    DBG("STORE/HANDLE CLOSE\n");
    OPENSSL_clear_free(ctx, sizeof(TPM2_HANDLE_CTX));
    return 1;
}

const OSSL_DISPATCH tpm2_handle_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))tpm2_handle_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))tpm2_handle_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_handle_settable_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))tpm2_handle_set_params },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))tpm2_handle_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))tpm2_handle_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))tpm2_handle_close },
    { 0, NULL }
};

