/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include <tss2/tss2_fapi.h>
#include <tss2/tss2_mu.h>
#include "tpm2-provider-pkey.h"

typedef struct tpm2_store_ctx_st TPM2_STORE_CTX;

struct tpm2_store_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_CAPABILITY capability;
    char *path;
    FAPI_CONTEXT *fapi_ctx;
    int load_done;
};

static OSSL_FUNC_store_open_fn tpm2_store_open;
static OSSL_FUNC_store_settable_ctx_params_fn tpm2_store_settable_params;
static OSSL_FUNC_store_set_ctx_params_fn tpm2_store_set_params;
static OSSL_FUNC_store_load_fn tpm2_store_load;
static OSSL_FUNC_store_eof_fn tpm2_store_eof;
static OSSL_FUNC_store_close_fn tpm2_store_close;

static void *
tpm2_store_open(void *provctx, const char *uri)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_STORE_CTX *sctx;
    TSS2_RC r;

    if (!uri || strncmp(uri, "tss2:", 5))
        return NULL;

    DBG("STORE/TSS2 OPEN %s\n", uri+5);
    if ((sctx = OPENSSL_zalloc(sizeof(TPM2_STORE_CTX))) == NULL)
        return NULL;

    sctx->core = cprov->core;
    sctx->esys_ctx = cprov->esys_ctx;
    sctx->capability = cprov->capability;

    if (!(sctx->path = strdup(uri+5)))
        goto error1;

    r = Fapi_Initialize(&sctx->fapi_ctx, NULL);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error2);

    return sctx;
error2:
    free(sctx->path);
error1:
    OPENSSL_clear_free(sctx, sizeof(TPM2_STORE_CTX));
    return NULL;
}

static const OSSL_PARAM *
tpm2_store_settable_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int
tpm2_store_set_params(void *loaderctx, const OSSL_PARAM params[])
{
    TRACE_PARAMS("STORE/TSS2 SET_PARAMS", params);
    return 1;
}

static int
tpm2_store_load_pkey(TPM2_STORE_CTX *sctx, ESYS_TR object,
                     OSSL_CALLBACK *object_cb, void *object_cbarg)
{
    TPM2B_PUBLIC *out_public = NULL;
    TPM2_PKEY *pkey = NULL;
    TSS2_RC r;
    int ret = 0;

    DBG("STORE/TSS2 LOAD pkey\n");
    pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY));
    if (pkey == NULL)
        return 0;

    pkey->core = sctx->core;
    pkey->esys_ctx = sctx->esys_ctx;
    pkey->capability = sctx->capability;
    pkey->object = object;

    r = Esys_ReadPublic(sctx->esys_ctx, object,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &out_public, NULL, NULL);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto final);

    pkey->data.pub = *out_public;
    pkey->data.privatetype = KEY_TYPE_HANDLE;
    Esys_TR_GetTpmHandle(sctx->esys_ctx, object, &pkey->data.handle);
    pkey->data.emptyAuth = 1;

    free(out_public);

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *keytype;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

    if ((keytype = tpm2_openssl_type(&pkey->data)) == NULL) {
        TPM2_ERROR_raise(sctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
        goto final;
    }
    DBG("STORE/TSS2 LOAD found %s\n", keytype);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)keytype, 0);
    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &pkey, sizeof(pkey));
    params[3] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);
final:
    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
    return ret;
}

static int
tpm2_store_load_index(TPM2_STORE_CTX *sctx, ESYS_TR object,
                      OSSL_CALLBACK *object_cb, void *object_cbarg)
{
    TPM2B_NV_PUBLIC *metadata = NULL;
    uint16_t read_len, read_max, data_len = 0;
    unsigned char *data = NULL;
    BIO *bufio;
    TSS2_RC r;
    int ret = 0;

    r = Esys_NV_ReadPublic(sctx->esys_ctx, object,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           &metadata, NULL);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto final);

    read_len = metadata->nvPublic.dataSize;
    read_max = tpm2_max_nvindex_buffer(sctx->capability.properties);
    DBG("STORE/TSS2 LOAD index %u bytes (buffer %u bytes)\n", read_len, read_max);

    if ((data = malloc(read_len)) == NULL)
        goto final;

    while (read_len > 0) {
        uint16_t bytes_to_read = read_len < read_max ? read_len : read_max;
        TPM2B_MAX_NV_BUFFER *buff = NULL;

        r = Esys_NV_Read(sctx->esys_ctx, object, object,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         bytes_to_read, data_len, &buff);
        TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto final);

        memcpy(data + data_len, buff->buffer, buff->size);
        read_len -= buff->size;
        data_len += buff->size;
        free(buff);
    }

    OSSL_PARAM params[3];
    int object_type = OSSL_OBJECT_UNKNOWN;
    char *pem_name = NULL;
    char *pem_header = NULL;
    unsigned char *der_data = NULL;
    long der_len;

    if ((bufio = BIO_new_mem_buf(data, data_len)) == NULL)
        goto final;

    /* the ossl_store_handle_load_result() supports DER objects only */
    if (PEM_read_bio(bufio, &pem_name, &pem_header, &der_data, &der_len) > 0) {
        if (pem_name != NULL) {
            DBG("STORE/TSS2 LOAD(PEM) %s %li bytes\n", pem_name, der_len);

            if (!strcmp(pem_name, TSSPRIVKEY_PEM_STRING))
                object_type = OSSL_OBJECT_PKEY;
            else if (!strcmp(pem_name, PEM_STRING_X509))
                object_type = OSSL_OBJECT_CERT;
            else if (!strcmp(pem_name, PEM_STRING_X509_CRL))
                object_type = OSSL_OBJECT_CRL;
        }

        /* pass the data to ossl_store_handle_load_result(),
           which will call the TPM2_PKEY decoder or read the certificate */
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

        params[1] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      der_data, der_len);
    } else {
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

        params[1] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      data, data_len);
    }

    params[2] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bufio);
final:
    free(data);
    free(metadata);
    return ret;
}

static int
tpm2_store_load(void *ctx,
                OSSL_CALLBACK *object_cb, void *object_cbarg,
                OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_STORE_CTX *sctx = ctx;
    uint8_t type;
    uint8_t *data = NULL;
    size_t length;
    TPMS_CONTEXT blob;
    ESYS_TR object;
    TSS2_RC r;
    int ret = 0;

    DBG("STORE/TSS2 LOAD\n");
    r = Fapi_GetEsysBlob(sctx->fapi_ctx, sctx->path, &type, &data, &length);
    sctx->load_done = 1;
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, return 0);

    switch(type) {
    case FAPI_ESYSBLOB_DESERIALIZE:
        r = Esys_TR_Deserialize(sctx->esys_ctx, data, length, &object);
        TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error1);
        break;
    case FAPI_ESYSBLOB_CONTEXTLOAD:
        r = Tss2_MU_TPMS_CONTEXT_Unmarshal(data, length, NULL, &blob);
        TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error1);

        r = Esys_ContextLoad(sctx->esys_ctx, &blob, &object);
        TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error1);
        break;
    default:
        TPM2_ERROR_raise(sctx->core, TPM2_ERR_CANNOT_LOAD_KEY);
        goto error1;
    }
    Fapi_Free(data);

    if (!strncmp(sctx->path, "/nv/", 4)) {
        ret = tpm2_store_load_index(sctx, object, object_cb, object_cbarg);
        Esys_TR_Close(sctx->esys_ctx, &object);
    } else {
        ret = tpm2_store_load_pkey(sctx, object, object_cb, object_cbarg);
        if (!ret)
            Esys_TR_Close(sctx->esys_ctx, &object);
    }

    return ret;
error2:
    Esys_TR_Close(sctx->esys_ctx, &object);
error1:
    Fapi_Free(data);
    return 0;
}

static int
tpm2_store_eof(void *ctx)
{
    TPM2_STORE_CTX *sctx = ctx;
    return sctx->load_done;
}

static int
tpm2_store_close(void *ctx)
{
    TPM2_STORE_CTX *sctx = ctx;

    if (sctx == NULL)
        return 0;

    DBG("STORE/TSS2 CLOSE\n");
    Fapi_Finalize(&sctx->fapi_ctx);
    free(sctx->path);

    OPENSSL_clear_free(ctx, sizeof(TPM2_STORE_CTX));
    return 1;
}

const OSSL_DISPATCH tpm2_tss2_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))tpm2_store_open },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_store_settable_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))tpm2_store_set_params },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))tpm2_store_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))tpm2_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))tpm2_store_close },
    { 0, NULL }
};

