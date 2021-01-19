/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * Copyright 2021, Petr Gotthard
 * All rights reserved.
 *
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
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_file_ctx_st TPM2_FILE_CTX;

struct tpm2_file_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    BIO *bin;
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
    DBG("STORE/FILE SET_PARAMS\n");
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
        goto error;

    if (!pkey->data.emptyAuth) {
        size_t plen = 0;
        /* request password; this might open an interactive user prompt */
        if (!pw_cb(pkey->userauth.buffer, sizeof(TPMU_HA), &plen, NULL, pw_cbarg)) {
            TPM2_ERROR_raise(fctx, TPM2TSS_R_GENERAL_FAILURE);
            goto error;
        }
        pkey->userauth.size = plen;
    }

    object_type = OSSL_OBJECT_PKEY;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

    if (pkey->data.pub.publicArea.type == TPM2_ALG_RSA)
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     "RSA", 0);
    else {
        TPM2_ERROR_raise(fctx, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &pkey, sizeof(pkey));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
error:
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

