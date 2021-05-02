/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * This implements a limited STORE, which supports PER and DER formats only.
 * Provided for user convenience. It can be used to load the TSS2 PRIVATE KEY
 * and X.509 certificates without loading the default provider.
 */

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
    BIO *bufbin;
    BIO *bin;
};

static OSSL_FUNC_store_open_fn tpm2_file_open;
static OSSL_FUNC_store_attach_fn tpm2_file_attach;
static OSSL_FUNC_store_settable_ctx_params_fn tpm2_file_settable_params;
static OSSL_FUNC_store_set_ctx_params_fn tpm2_file_set_params;
static OSSL_FUNC_store_load_fn tpm2_file_load;
static OSSL_FUNC_store_eof_fn tpm2_file_eof;
static OSSL_FUNC_store_close_fn tpm2_file_close;

static void *
tpm2_file_open(void *provctx, const char *uri)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_FILE_CTX *ctx = NULL;
    BIO *bio;

    DBG("STORE/FILE OPEN %s\n", uri);
    bio = BIO_new_file(uri, "rb");
    if (!bio) {
        ERR_clear_error();
        return NULL;
    }

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
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_FILE_CTX *ctx;

    DBG("STORE/FILE ATTACH\n");
    if ((ctx = OPENSSL_zalloc(sizeof(TPM2_FILE_CTX))) == NULL)
        return NULL;

    ctx->core = cprov->core;
    ctx->esys_ctx = cprov->esys_ctx;

    if ((ctx->bin = bio_new_from_core_bio(cprov->corebiometh, cin)) == NULL)
        goto error;

    /* decoding will require tell-seek operations */
    if (BIO_tell(ctx->bin) < 0) {
        ctx->bufbin = BIO_new(BIO_f_readbuffer());
        if (ctx->bufbin == NULL) {
            BIO_free(ctx->bin);
            goto error;
        }
        ctx->bin = BIO_push(ctx->bufbin, ctx->bin);
    }

    return ctx;
error:
    OPENSSL_clear_free(ctx, sizeof(TPM2_FILE_CTX));
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

/* ASN1_d2i_bio helper to retrieve raw ASN.1 data */
static void *
d2i_raw(void **x, const unsigned char **p, long len)
{
    unsigned char *buf;

    if ((buf = OPENSSL_malloc(len)) == NULL)
        return NULL;

    memcpy(buf, *p, len);
    *(long *)x = len;

    return buf;
}

static int
tpm2_file_load(void *ctx,
               OSSL_CALLBACK *object_cb, void *object_cbarg,
               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_FILE_CTX *fctx = ctx;
    char *pem_name = NULL;
    char *pem_header = NULL;
    unsigned char *der_data;
    long der_len;
    OSSL_PARAM params[3];
    int object_type = OSSL_OBJECT_UNKNOWN;
    int fpos, ret;

    DBG("STORE/FILE LOAD\n");
    if ((fpos = BIO_tell(fctx->bin)) == -1)
        return 0;
    /* try to read PEM */
    if (!PEM_read_bio(fctx->bin, &pem_name, &pem_header, &der_data, &der_len)) {
        unsigned long last = ERR_peek_error();
        if (ERR_GET_REASON(last) != PEM_R_NO_START_LINE)
            return 0;
        ERR_clear_error();

        /* rewind back */
        if (BIO_seek(fctx->bin, fpos) == -1)
            return 0;
        /* try to read raw DER */
        der_data = ASN1_d2i_bio(NULL, d2i_raw, fctx->bin, (void **)&der_len);
        if(der_data == NULL) {
            if (!BIO_eof(fctx->bin))
                return 0;
            ERR_clear_error();
            return 1;
        }
    }

    if (pem_name != NULL) {
        DBG("STORE/FILE LOAD(PEM) %s\n", pem_name);

        if (!strcmp(pem_name, TSSPRIVKEY_PEM_STRING))
            object_type = OSSL_OBJECT_PKEY;
        else if (!strcmp(pem_name, PEM_STRING_X509))
            object_type = OSSL_OBJECT_CERT;
        else if (!strcmp(pem_name, PEM_STRING_X509_CRL))
            object_type = OSSL_OBJECT_CRL;
    }

    /* pass the data to ossl_store_handle_load_result(),
       which will call the TPM2_PKEY decoder or read the certificate  */
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                  der_data, der_len);
    params[2] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
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

    if (fctx->bufbin != NULL) {
        fctx->bin = BIO_pop(fctx->bufbin);
        BIO_free(fctx->bufbin);
    }
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

