/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * This implements a decoder for context objects created by the tpm2-tools.
 */

#include <string.h>
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"
#include "tpm2-provider-types.h"

typedef struct tpm2_ctx_decoder_ctx_st TPM2_CTX_DECODER_CTX;

struct tpm2_ctx_decoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
    ESYS_CONTEXT *esys_ctx;
};

static OSSL_FUNC_decoder_newctx_fn tpm2_ctx_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn tpm2_ctx_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn tpm2_ctx_decoder_decode;

static void *
tpm2_ctx_decoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_CTX_DECODER_CTX *cctx = OPENSSL_zalloc(sizeof(TPM2_CTX_DECODER_CTX));

    if (cctx == NULL)
        return NULL;

    cctx->core = cprov->core;
    cctx->libctx = cprov->libctx;
    cctx->esys_ctx = cprov->esys_ctx;
    return cctx;
}

static void
tpm2_ctx_decoder_freectx(void *ctx)
{
    TPM2_CTX_DECODER_CTX *cctx = ctx;

    OPENSSL_clear_free(cctx, sizeof(TPM2_CTX_DECODER_CTX));
}

/* the file format is defined in tpm2-tools/lib/files.c */
static const uint32_t MAGIC = 0xBADCC0DE;
#define CONTEXT_VERSION 1

#define DEFINE_BIO_READ(size) \
    static int \
    BIO_read_uint##size(BIO *b, uint##size##_t *val) \
    { \
        uint##size##_t v; \
        if (BIO_read(b, &v, sizeof(uint##size##_t)) == sizeof(uint##size##_t)) { \
            *val = be##size##toh(v); \
            return 1; \
        } \
        return 0; \
    }

DEFINE_BIO_READ(16)
DEFINE_BIO_READ(32)
DEFINE_BIO_READ(64)

static int
read_context(BIO *bin, TPMS_CONTEXT *context)
{
    uint32_t magic, version;

    if (!BIO_read_uint32(bin, &magic) || magic != MAGIC
            || !BIO_read_uint32(bin, &version) || version != CONTEXT_VERSION
            || !BIO_read_uint32(bin, &context->hierarchy)
            || !BIO_read_uint32(bin, &context->savedHandle)
            || !BIO_read_uint64(bin, &context->sequence)
            || !BIO_read_uint16(bin, &context->contextBlob.size)
            || context->contextBlob.size > sizeof(context->contextBlob.buffer)
            || BIO_read(bin, context->contextBlob.buffer, context->contextBlob.size)
                != context->contextBlob.size) {
        /* this is not our file */
        return 0;
    }

    DBG("CTX DECODER loaded\n");
    return 1;
}

static int
tpm2_ctx_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
                        OSSL_CALLBACK *object_cb, void *object_cbarg,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_CTX_DECODER_CTX *cctx = ctx;
    BIO *bin;
    TPMS_CONTEXT context;
    OSSL_PARAM params[3];
    int res = 0;

    DBG("CTX DECODER DECODE\n");
    if ((bin = BIO_new_from_core_bio(cctx->libctx, cin)) == NULL)
        return 0;

    if (read_context(bin, &context)) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      &context, sizeof(TPMS_CONTEXT));
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                     "TPMS_CONTEXT", 0);
        params[2] = OSSL_PARAM_construct_end();

        res = object_cb(params, object_cbarg);
    } else {
        /* We return "empty handed". This is not an error. */
        res = 1;
    }

    BIO_free(bin);
    return res;
}

const OSSL_DISPATCH tpm2_ctx_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_ctx_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_ctx_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_ctx_decoder_decode },
    { 0, NULL }
};

