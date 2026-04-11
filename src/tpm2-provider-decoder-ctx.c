/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-ctx.h"
#include "tpm2-provider-pkey.h"

typedef struct tpm2_ctx_decoder_ctx_st TPM2_CTX_DECODER_CTX;

struct tpm2_ctx_decoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
    tpm2_semaphore_t esys_lock;
    ESYS_CONTEXT *esys_ctx;
    TPM2_CAPABILITY capability;
};

static OSSL_FUNC_decoder_newctx_fn tpm2_ctx_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn tpm2_ctx_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn tpm2_ctx_decoder_decode_rsa;
static OSSL_FUNC_decoder_decode_fn tpm2_ctx_decoder_decode_ec;
static OSSL_FUNC_decoder_export_object_fn tpm2_ctx_decoder_export_object;

static void *
tpm2_ctx_decoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_CTX_DECODER_CTX *cctx = OPENSSL_zalloc(sizeof(TPM2_CTX_DECODER_CTX));

    if (cctx == NULL)
        return NULL;

    cctx->core = cprov->core;
    cctx->libctx = cprov->libctx;
    cctx->esys_lock = cprov->esys_lock;
    cctx->esys_ctx = cprov->esys_ctx;
    cctx->capability = cprov->capability;

    return cctx;
}

static void
tpm2_ctx_decoder_freectx(void *ctx)
{
    TPM2_CTX_DECODER_CTX *cctx = ctx;

    OPENSSL_clear_free(cctx, sizeof(TPM2_CTX_DECODER_CTX));
}

static int
tpm2_ctx_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
                        int expected_type,
                        OSSL_CALLBACK *object_cb, void *object_cbarg,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_CTX_DECODER_CTX *cctx = ctx;
    BIO *bin = NULL;
    TPMS_CONTEXT context;
    TPM2B_PUBLIC *out_public = NULL;
    TPM2_PKEY *pkey = NULL;
    TSS2_RC r;
    int res = 0;

    DBG("CTX DECODER DECODE 0x%x\n", selection);

    if (selection != 0 && (selection & OSSL_KEYMGMT_SELECT_ALL) == 0) {
        res = 1; /* We return "empty handed". This is not an error. */
        goto final1;
    }

    bin = BIO_new_from_core_bio(cctx->libctx, cin);
    if (bin == NULL)
        return 0;

    if (!tpm2_read_context(bin, &context)) {
        res = 1; /* We return "empty handed". This is not an error. */
        goto final1;
    }

    pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY));
    if (pkey == NULL)
        goto final1;

    pkey->core = cctx->core;
    pkey->esys_lock = cctx->esys_lock;
    pkey->esys_ctx = cctx->esys_ctx;
    pkey->capability = cctx->capability;

    if (!tpm2_semaphore_lock(cctx->esys_lock))
        goto final2;
    r = Esys_ContextLoad(cctx->esys_ctx, &context, &pkey->object);
    if (!r) {
        r = Esys_ReadPublic(cctx->esys_ctx, pkey->object,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &out_public, NULL, NULL);
        if (!r) {
            pkey->data.pub = *out_public;
            Esys_Free(out_public);
            pkey->data.privatetype = KEY_TYPE_HANDLE;
            r = Esys_TR_GetTpmHandle(cctx->esys_ctx, pkey->object, &pkey->data.handle);
        }
    }
    tpm2_semaphore_unlock(cctx->esys_lock);
    TPM2_CHECK_RC(cctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto final2);

    if (pkey->data.pub.publicArea.type != expected_type) {
        res = 1; /* We return "empty handed". This is not an error. */
        goto final2;
    }

    TPM2B_DIGEST userauth;
    size_t plen = 0;

    /* request password; this might open an interactive user prompt */
    if (!pw_cb((char *)userauth.buffer, sizeof(TPMU_HA), &plen, NULL, pw_cbarg)) {
        TPM2_ERROR_raise(cctx->core, TPM2_ERR_AUTHORIZATION_FAILURE);
        goto final2;
    }
    userauth.size = plen;

    if (!tpm2_semaphore_lock(cctx->esys_lock))
        goto final2;
    r = Esys_TR_SetAuth(cctx->esys_ctx, pkey->object, &userauth);
    tpm2_semaphore_unlock(cctx->esys_lock);
    TPM2_CHECK_RC(cctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto final2);

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *keytype;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

    if ((keytype = tpm2_openssl_type(&pkey->data)) == NULL) {
        TPM2_ERROR_raise(cctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
        goto final2;
    }
    DBG("CTX DECODER DECODE found %s\n", keytype);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)keytype, 0);
    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &pkey, sizeof(pkey));
    params[3] = OSSL_PARAM_construct_end();

    if (object_cb(params, object_cbarg)) {
        BIO_free(bin);
        return 1;
    }
final2:
    if (pkey->object != ESYS_TR_NONE)
        tpm2_esys_tr_close(pkey->esys_lock, pkey->esys_ctx, &pkey->object);
    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
final1:
    BIO_free(bin);
    return res;
}

static int
tpm2_ctx_decoder_decode_rsa(void *ctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *object_cb, void *object_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return tpm2_ctx_decoder_decode(ctx, cin, selection, TPM2_ALG_RSA,
                                   object_cb, object_cbarg, pw_cb, pw_cbarg);
}

static int
tpm2_ctx_decoder_decode_ec(void *ctx, OSSL_CORE_BIO *cin, int selection,
                           OSSL_CALLBACK *object_cb, void *object_cbarg,
                           OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return tpm2_ctx_decoder_decode(ctx, cin, selection, TPM2_ALG_ECC,
                                   object_cb, object_cbarg, pw_cb, pw_cbarg);
}

static int
tpm2_ctx_decoder_export_object(void *ctx, const void *objref, size_t objref_sz,
                               OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    TPM2_PKEY *keydata;

    DBG("CTX DECODER EXPORT_OBJECT\n");
    if (objref_sz == sizeof(keydata)) {
        /* The contents of the reference is the address to our object */
        keydata = *(TPM2_PKEY **)objref;

        if (keydata->data.pub.publicArea.type == TPM2_ALG_RSA)
            return tpm2_rsa_keymgmt_export(keydata, OSSL_KEYMGMT_SELECT_ALL,
                                           export_cb, export_cbarg);
        else if (keydata->data.pub.publicArea.type == TPM2_ALG_ECC)
            return tpm2_ec_keymgmt_export(keydata, OSSL_KEYMGMT_SELECT_ALL,
                                          export_cb, export_cbarg);
    }

    return 0;
}

const OSSL_DISPATCH tpm2_ctx_to_rsa_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_ctx_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_ctx_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_ctx_decoder_decode_rsa },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))tpm2_ctx_decoder_export_object },
    { 0, NULL }
};

const OSSL_DISPATCH tpm2_ctx_to_ec_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_ctx_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_ctx_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_ctx_decoder_decode_ec },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))tpm2_ctx_decoder_export_object },
    { 0, NULL }
};
