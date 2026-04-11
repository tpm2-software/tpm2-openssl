/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * This implements a type-specific PEM->TSS2 decoder that consumes the
 * 'TSS2 PRIVATE KEY' format only. It is used by the default STORE only.
 */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_pem_decoder_ctx_st TPM2_PEM_DECODER_CTX;

struct tpm2_pem_decoder_ctx_st {
    OSSL_LIB_CTX *libctx;
};

static OSSL_FUNC_decoder_newctx_fn tpm2_pem_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn tpm2_pem_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn tpm2_pem_decoder_decode;

static void *
tpm2_pem_decoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_PEM_DECODER_CTX *dctx = OPENSSL_zalloc(sizeof(TPM2_PEM_DECODER_CTX));

    if (dctx == NULL)
        return NULL;

    dctx->libctx = cprov->libctx;
    return dctx;
}

static void
tpm2_pem_decoder_freectx(void *ctx)
{
    TPM2_PEM_DECODER_CTX *dctx = ctx;

    OPENSSL_clear_free(dctx, sizeof(TPM2_PEM_DECODER_CTX));
}

static int
tpm2_pem_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
                        OSSL_CALLBACK *object_cb, void *object_cbarg,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_PEM_DECODER_CTX *dctx = ctx;
    BIO *bin;
    char *pem_name = NULL;
    char *pem_header = NULL;
    unsigned char *der_data = NULL;
    long der_len;
    OSSL_PARAM params[3];
    int res;

    DBG("PEM DECODER DECODE\n");
    if ((bin = BIO_new_from_core_bio(dctx->libctx, cin)) == NULL)
        return 0;

    if (PEM_read_bio(bin, &pem_name, &pem_header, &der_data, &der_len) > 0
            && strcmp(pem_name, TSSPRIVKEY_PEM_STRING) == 0) {
        DBG("PEM DECODER DECODE success\n");
        /* submit the loaded key */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      der_data, der_len);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                     "TSS2", 0);
        params[2] = OSSL_PARAM_construct_end();

        res = object_cb(params, object_cbarg);
    } else {
        /* We return "empty handed". This is not an error. */
        res = 1;
    }

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bin);
    return res;
}

const OSSL_DISPATCH tpm2_pem_to_tss2_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_pem_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_pem_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_pem_decoder_decode },
    { 0, NULL }
};
