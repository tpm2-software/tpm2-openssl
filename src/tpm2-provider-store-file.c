/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/err.h>

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
    TRACE_PARAMS("STORE/FILE SET_PARAMS", params);
    return 1;
}

static int
tpm2_file_load(void *ctx,
               OSSL_CALLBACK *object_cb, void *object_cbarg,
               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_FILE_CTX *fctx = ctx;
    char *pem_name, *pem_header;
    unsigned char *pem_data;
    long pem_len;
    OSSL_PARAM params[3];
    int object_type, ret;

    if (!PEM_read_bio(fctx->bin, &pem_name, &pem_header, &pem_data, &pem_len)) {
        unsigned long last = ERR_peek_error();
        if (ERR_GET_REASON(last) == PEM_R_NO_START_LINE) {
            ERR_clear_error();
            return 0; /* no more data */
        } else
            return -1; /* some other error */
    }

    /* this is PEM */
    DBG("STORE/FILE LOAD(PEM) %s\n", pem_name);

    if (!strcmp(pem_name, TSSPRIVKEY_PEM_STRING))
        object_type = OSSL_OBJECT_PKEY;
    else if (!strcmp(pem_name, PEM_STRING_X509))
        object_type = OSSL_OBJECT_CERT;
    else
        object_type = OSSL_OBJECT_UNKNOWN;

    /* pass the data to ossl_store_handle_load_result(),
       which will call the TPM2_PKEY decoder or read the certificate  */
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                  pem_data, pem_len);
    params[2] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(pem_data);
    return ret;
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

    if (fctx == NULL)
        return 0;

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

