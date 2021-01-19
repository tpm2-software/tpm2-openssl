/*******************************************************************************
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

typedef struct tpm2_rsa_decoder_ctx_st TPM2_RSA_DECODER_CTX;

struct tpm2_rsa_decoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    BIO_METHOD *corebiometh;
    ESYS_CONTEXT *esys_ctx;
};

static void *
text2key_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_DECODER_CTX *dctx = OPENSSL_zalloc(sizeof(TPM2_RSA_DECODER_CTX));

    DBG("ENCODER NEW\n");
    if (dctx == NULL)
        return NULL;

    dctx->core = cprov->core;
    dctx->corebiometh = cprov->corebiometh;
    dctx->esys_ctx = cprov->esys_ctx;
    return dctx;
}

static void
text2key_freectx(void *ctx)
{
    TPM2_RSA_DECODER_CTX *dctx = ctx;

    DBG("ENCODER FREE\n");
    OPENSSL_clear_free(dctx, sizeof(TPM2_RSA_DECODER_CTX));
}

static const
OSSL_PARAM *text2key_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DECODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_DECODER_PARAM_INPUT_STRUCTURE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int
text2key_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pem"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_STRUCTURE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pkcs8"))
        return 0;

    return 1;
}

static int
text2key_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
                OSSL_CALLBACK *data_cb, void *data_cbarg,
                OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_RSA_DECODER_CTX *dctx = ctx;
    TPM2_PKEY *pkey;
    BIO *bin;
    OSSL_PARAM params[4];
    int object_type;
    int ret;

    DBG("DECODER DECODE\n");
    pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY));
    if (pkey == NULL)
        return 0;

    pkey->core = dctx->core;
    pkey->esys_ctx = dctx->esys_ctx;
    pkey->object = ESYS_TR_NONE;

    bin = bio_new_from_core_bio(dctx->corebiometh, cin);
    if (bin == NULL)
        goto error;

    ret = tpm2_keydata_read(bin, &pkey->data);
    BIO_free(bin);
    if (ret <= 0)
        goto error;

    if (!pkey->data.emptyAuth) {
        size_t plen = 0;

        if (!pw_cb(pkey->userauth.buffer, sizeof(TPM2B_DIGEST), &plen, NULL, pw_cbarg))
            goto error;
        pkey->userauth.size = plen;
    }

    object_type = OSSL_OBJECT_PKEY;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 "RSA", 0);
    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &pkey, sizeof(pkey));
    params[3] = OSSL_PARAM_construct_end();

    ret = data_cb(params, data_cbarg);

error:
    /* key managers that grabbed the pointer have also set this to NULL */
    if (pkey != NULL)
        OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));

    return ret;
}

const OSSL_DISPATCH tpm2_rsa_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))text2key_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))text2key_freectx },
    { OSSL_FUNC_DECODER_GETTABLE_PARAMS, (void (*)(void))text2key_gettable_params },
    { OSSL_FUNC_DECODER_GET_PARAMS, (void (*)(void))text2key_get_params },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))text2key_decode },
    { 0, NULL }
};

