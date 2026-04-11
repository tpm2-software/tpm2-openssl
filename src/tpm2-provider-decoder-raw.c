/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-ctx.h"

typedef struct tpm2_raw_decoder_ctx_st TPM2_RAW_DECODER_CTX;

struct tpm2_raw_decoder_ctx_st {
    OSSL_LIB_CTX *libctx;
};

static OSSL_FUNC_decoder_newctx_fn tpm2_raw_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn tpm2_raw_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn tpm2_raw_decoder_decode;

static void *
tpm2_raw_decoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RAW_DECODER_CTX *cctx = OPENSSL_zalloc(sizeof(TPM2_RAW_DECODER_CTX));

    if (cctx == NULL)
        return NULL;

    cctx->libctx = cprov->libctx;
    return cctx;
}

static void
tpm2_raw_decoder_freectx(void *ctx)
{
    TPM2_RAW_DECODER_CTX *cctx = ctx;

    OPENSSL_clear_free(cctx, sizeof(TPM2_RAW_DECODER_CTX));
}

static int
tpm2_raw_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
                        OSSL_CALLBACK *object_cb, void *object_cbarg,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_RAW_DECODER_CTX *cctx = ctx;
    BIO *bin;
    unsigned char *ctx_data = NULL;
    size_t ctx_len;

    OSSL_PARAM params[3];
    int res = 0;

    DBG("RAW DECODER DECODE\n");
    if ((bin = BIO_new_from_core_bio(cctx->libctx, cin)) == NULL)
        return 0;

    if (tpm2_read_context_raw(bin, &ctx_data, &ctx_len)) {
        DBG("RAW DECODER DECODE success\n");
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      ctx_data, ctx_len);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                     "TPMS_CONTEXT", 0);
        params[2] = OSSL_PARAM_construct_end();

        res = object_cb(params, object_cbarg);
    } else {
        /* We return "empty handed". This is not an error. */
        res = 1;
    }

    OPENSSL_free(ctx_data);
    BIO_free(bin);
    return res;
}

const OSSL_DISPATCH tpm2_raw_to_ctx_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_raw_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_raw_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_raw_decoder_decode },
    { 0, NULL }
};
