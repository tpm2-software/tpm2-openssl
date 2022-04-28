/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_object_ctx_st TPM2_OBJECT_CTX;

struct tpm2_object_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_CAPABILITY capability;
    int has_pass;
    TPM2_HANDLE handle;
    BIO *bio;
    int load_done;
};

static OSSL_FUNC_store_open_fn tpm2_object_open;
static OSSL_FUNC_store_attach_fn tpm2_object_attach;
static OSSL_FUNC_store_settable_ctx_params_fn tpm2_object_settable_params;
static OSSL_FUNC_store_set_ctx_params_fn tpm2_object_set_params;
static OSSL_FUNC_store_load_fn tpm2_object_load;
static OSSL_FUNC_store_eof_fn tpm2_object_eof;
static OSSL_FUNC_store_close_fn tpm2_object_close;

static void *
tpm2_object_open(void *provctx, const char *uri)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_OBJECT_CTX *ctx;
    char *baseuri, *opts;

    DBG("STORE/OBJECT OPEN %s\n", uri);
    if ((ctx = OPENSSL_zalloc(sizeof(TPM2_OBJECT_CTX))) == NULL)
        return NULL;

    ctx->core = cprov->core;
    ctx->esys_ctx = cprov->esys_ctx;
    ctx->capability = cprov->capability;

    if ((baseuri = OPENSSL_strdup(uri)) == NULL)
        goto error1;
    if ((opts = strchr(baseuri, '?')) != NULL) {
        *opts = 0;

        if (!strncmp(opts+1, "pass", 4))
            ctx->has_pass = 1;
        else
            goto error2;
    }

    /* the object is stored in a file */
    if (!strncmp(baseuri, "object:", 7)) {
        if ((ctx->bio = BIO_new_file(baseuri+7, "rb")) == NULL)
            goto error2;
    /* the object is persisted under a specific handle */
    } else if (!strncmp(baseuri, "handle:", 7)) {
        unsigned long int value;
        char *end_ptr = NULL;

        value = strtoul(baseuri+7, &end_ptr, 16);
        if (*end_ptr != 0 || value > UINT32_MAX)
            goto error2;

        ctx->handle = value;
    } else
        goto error2;

    OPENSSL_free(baseuri);
    return ctx;
error2:
    OPENSSL_free(baseuri);
error1:
    OPENSSL_clear_free(ctx, sizeof(TPM2_OBJECT_CTX));
    return NULL;
}

static void *
tpm2_object_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_OBJECT_CTX *ctx;

    DBG("STORE/OBJECT ATTACH\n");
    if ((ctx = OPENSSL_zalloc(sizeof(TPM2_OBJECT_CTX))) == NULL)
        return NULL;

    ctx->core = cprov->core;
    ctx->esys_ctx = cprov->esys_ctx;
    ctx->capability = cprov->capability;

    if ((ctx->bio = BIO_new_from_core_bio(cprov->libctx, cin)) == NULL)
        goto error;

    return ctx;
error:
    OPENSSL_clear_free(ctx, sizeof(TPM2_OBJECT_CTX));
    return NULL;
}

static const OSSL_PARAM *
tpm2_object_settable_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int
tpm2_object_set_params(void *loaderctx, const OSSL_PARAM params[])
{
    TRACE_PARAMS("STORE/OBJECT SET_PARAMS", params);
    return 1;
}

static int
read_until_eof(BIO *bio, uint8_t **buffer)
{
    int size = 1024;
    int len = 0;

    if ((*buffer = OPENSSL_malloc(size)) == NULL)
        return -1;
    /* read until the end-of-file */
    do {
        int res;

        if (size - len < 64) {
            uint8_t *newbuff;

            size += 1024;
            if ((newbuff = OPENSSL_realloc(*buffer, size)) == NULL)
                goto error;

            *buffer = newbuff;
        }

        res = BIO_read(bio, *buffer + len, size - len);
        if (res < 0)
            goto error;
        len += res;
    } while (!BIO_eof(bio));

    return len;
error:
    OPENSSL_free(*buffer);
    return -1;
}

static int
tpm2_object_load_pkey(TPM2_OBJECT_CTX *sctx, ESYS_TR object,
                      OSSL_CALLBACK *object_cb, void *object_cbarg)
{
    TPM2B_PUBLIC *out_public = NULL;
    TPM2_PKEY *pkey = NULL;
    TSS2_RC r;
    int ret = 0;

    DBG("STORE/OBJECT LOAD pkey\n");
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
    pkey->data.handle = sctx->handle;
    if (!sctx->has_pass)
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
    DBG("STORE/OBJECT LOAD found %s\n", keytype);
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
tpm2_object_load_index(TPM2_OBJECT_CTX *sctx, ESYS_TR object,
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
    DBG("STORE/OBJECT LOAD index %u bytes (buffer %u bytes)\n", read_len, read_max);

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
            DBG("STORE/OBJECT LOAD(PEM) %s %li bytes\n", pem_name, der_len);

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
tpm2_object_load(void *ctx,
                 OSSL_CALLBACK *object_cb, void *object_cbarg,
                 OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_OBJECT_CTX *sctx = ctx;
    ESYS_TR object;
    TSS2_RC r;
    int ret = 0;

    DBG("STORE/OBJECT LOAD\n");
    if (sctx->bio) {
        uint8_t *buffer;
        int buffer_size;

        if ((buffer_size = read_until_eof(sctx->bio, &buffer)) < 0)
            return 0;
        /* read object metadata */
        r = Esys_TR_Deserialize(sctx->esys_ctx, buffer, buffer_size, &object);
        OPENSSL_free(buffer);
        /* TODO: should use Esys_TR_GetTpmHandle */
        sctx->handle = TPM2_HR_PERSISTENT;
    } else {
        /* create reference to a pre-existing TPM object */
        r = Esys_TR_FromTPMPublic(sctx->esys_ctx, sctx->handle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &object);
        sctx->load_done = 1;
    }
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, return 0);

    if (sctx->has_pass) {
        TPM2B_DIGEST userauth;
        size_t plen = 0;

        /* request password; this might open an interactive user prompt */
        if (!pw_cb((char *)userauth.buffer, sizeof(TPMU_HA), &plen, NULL, pw_cbarg)) {
            TPM2_ERROR_raise(sctx->core, TPM2_ERR_AUTHORIZATION_FAILURE);
            goto error;
        }
        userauth.size = plen;

        r = Esys_TR_SetAuth(sctx->esys_ctx, object, &userauth);
        TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error);
    }

    UINT8 tag = (sctx->handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT;
    switch (tag) {
    case TPM2_HT_TRANSIENT:
    case TPM2_HT_PERSISTENT:
        ret = tpm2_object_load_pkey(sctx, object, object_cb, object_cbarg);
        if (!ret)
            Esys_TR_Close(sctx->esys_ctx, &object);
        break;
    case TPM2_HT_NV_INDEX:
        ret = tpm2_object_load_index(sctx, object, object_cb, object_cbarg);
        Esys_TR_Close(sctx->esys_ctx, &object);
        break;
    }

    return ret;
error:
    Esys_TR_Close(sctx->esys_ctx, &object);
    return 0;
}

static int
tpm2_object_eof(void *ctx)
{
    TPM2_OBJECT_CTX *sctx = ctx;
    return (sctx->bio && BIO_eof(sctx->bio)) || sctx->load_done;
}

static int
tpm2_object_close(void *ctx)
{
    TPM2_OBJECT_CTX *sctx = ctx;

    if (sctx == NULL)
        return 0;

    DBG("STORE/OBJECT CLOSE\n");
    BIO_free(sctx->bio);

    OPENSSL_clear_free(ctx, sizeof(TPM2_OBJECT_CTX));
    return 1;
}

const OSSL_DISPATCH tpm2_object_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))tpm2_object_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))tpm2_object_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_object_settable_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))tpm2_object_set_params },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))tpm2_object_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))tpm2_object_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))tpm2_object_close },
    { 0, NULL }
};

