/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
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

#include "tpm2-provider.h"

typedef struct tpm2_handle_ctx_st TPM2_HANDLE_CTX;

struct tpm2_handle_ctx_st {
    TPM2_PROVIDER_CTX *prov_ctx;
    TPM2_HANDLE handle;
    int load_done;
};

static void *
handle_open(void *provctx, const char *uri)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    unsigned long int value;
    char *end_ptr = NULL;
    TPM2_HANDLE_CTX *ctx = NULL;

    printf("OPEN\n");
    if (!strncmp(uri, "handle:", 7))
    {
        value = strtoul(uri+7, &end_ptr, 16);
        if (*end_ptr != 0 || value > UINT32_MAX)
            return NULL;
    }
    else
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(TPM2_HANDLE_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->prov_ctx = cprov;
    ctx->handle = value;
    return ctx;
}

static void *
handle_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    printf("ATTACH\n");
    // attach operation is required, but not supported
    return NULL;
}

static const OSSL_PARAM *
handle_settable_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int
handle_set_params(void *loaderctx, const OSSL_PARAM params[])
{
    printf("SET PARAMS\n");
    return 1;
}

static int
handle_load(void *ctx,
            OSSL_CALLBACK *object_cb, void *object_cbarg,
            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_HANDLE_CTX *csto = ctx;
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC *out_public = NULL;
    TPM2_DATA *tpm2Data = NULL;
    TSS2_RC r;

    printf("LOAD\n");

    r = Esys_TR_FromTPMPublic(csto->prov_ctx->esys_ctx, csto->handle,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &keyHandle);
    if (r != TPM2_RC_SUCCESS)
        return 0;

    r = Esys_ReadPublic(csto->prov_ctx->esys_ctx, keyHandle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &out_public, NULL, NULL);
    if (r != TPM2_RC_SUCCESS)
        return 0;

    tpm2Data = OPENSSL_zalloc(sizeof(TPM2_DATA));
    if (tpm2Data == NULL)
    {
        free(out_public);
        return 0;
    }

    tpm2Data->pub = *out_public;
    tpm2Data->privatetype = KEY_TYPE_HANDLE;
    tpm2Data->handle = csto->handle;

    free(out_public);
    csto->load_done = 1;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    // TODO: to support ECDSA keys we will need to actually read the key info
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 "RSA", 0);
    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &tpm2Data, sizeof(tpm2Data));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
}

static int
handle_eof(void *ctx)
{
    TPM2_HANDLE_CTX *csto = ctx;
    return csto->load_done;
}

static int
handle_close(void *ctx)
{
    printf("CLOSE\n");
    OPENSSL_clear_free(ctx, sizeof(TPM2_HANDLE_CTX));
    return 1;
}

const OSSL_DISPATCH tpm2_handle_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))handle_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))handle_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void(*)(void))handle_settable_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))handle_set_params },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))handle_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))handle_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))handle_close },
    { 0, NULL }
};

