/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * This implements a DER->PKEY decoder for the 'TSS2 PRIVATE KEY' type. It can
 * be used with any STORE implementation.
 */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"
#include "tpm2-provider-types.h"

typedef struct tpm2_tss2_decoder_ctx_st TPM2_TSS2_DECODER_CTX;

struct tpm2_tss2_decoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    BIO_METHOD *corebiometh;
    ESYS_CONTEXT *esys_ctx;
    TPMS_CAPABILITY_DATA *capability;
    TPM2B_DIGEST parentAuth;
};

static OSSL_FUNC_decoder_newctx_fn tpm2_tss2_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn tpm2_tss2_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn tpm2_tss2_decoder_decode_rsa;
static OSSL_FUNC_decoder_decode_fn tpm2_tss2_decoder_decode_ec;
static OSSL_FUNC_decoder_export_object_fn tpm2_tss2_decoder_export_object;

static void *
tpm2_tss2_decoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_TSS2_DECODER_CTX *dctx = OPENSSL_zalloc(sizeof(TPM2_TSS2_DECODER_CTX));

    if (dctx == NULL)
        return NULL;

    dctx->core = cprov->core;
    dctx->corebiometh = cprov->corebiometh;
    dctx->esys_ctx = cprov->esys_ctx;
    dctx->capability = cprov->capability;
    return dctx;
}

static void
tpm2_tss2_decoder_freectx(void *ctx)
{
    TPM2_TSS2_DECODER_CTX *dctx = ctx;

    OPENSSL_clear_free(dctx, sizeof(TPM2_TSS2_DECODER_CTX));
}

static const char *
decode_privkey(TPM2_TSS2_DECODER_CTX *dctx, TPM2_PKEY *pkey,
               BIO *bin, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TSS2_RC r = 0;
    const char *keytype;

    if (!tpm2_keydata_read(bin, &pkey->data, KEY_FORMAT_DER))
        return NULL;

    if (pkey->data.privatetype == KEY_TYPE_BLOB) {
        ESYS_TR parent = ESYS_TR_NONE;

        if (pkey->data.parent && pkey->data.parent != TPM2_RH_OWNER) {
            DBG("TSS2 DECODER LOAD parent: persistent 0x%x\n", pkey->data.parent);
            if (!tpm2_load_parent(pkey->core, pkey->esys_ctx,
                                  pkey->data.parent, &dctx->parentAuth, &parent))
                goto error1;
        } else {
            DBG("TSS2 DECODER LOAD parent: primary 0x%x\n", TPM2_RH_OWNER);
            if (!tpm2_build_primary(pkey->core, pkey->esys_ctx, pkey->capability,
                                    ESYS_TR_RH_OWNER, &dctx->parentAuth, &parent))
                goto error1;
        }

        r = Esys_Load(pkey->esys_ctx, parent,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      &pkey->data.priv, &pkey->data.pub, &pkey->object);

        if (pkey->data.parent && pkey->data.parent != TPM2_RH_OWNER)
            Esys_TR_Close(pkey->esys_ctx, &parent);
        else
            Esys_FlushContext(pkey->esys_ctx, parent);

        TPM2_CHECK_RC(pkey->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error1);
    } else if (pkey->data.privatetype == KEY_TYPE_HANDLE) {
        r = Esys_TR_FromTPMPublic(pkey->esys_ctx, pkey->data.handle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &pkey->object);
        TPM2_CHECK_RC(pkey->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error1);
    } else {
        TPM2_ERROR_raise(pkey->core, TPM2_ERR_INPUT_CORRUPTED);
        goto error1;
    }

    if (!pkey->data.emptyAuth) {
        TPM2B_DIGEST userauth;
        size_t plen = 0;

        /* request password; this might open an interactive user prompt */
        if (!pw_cb((char *)userauth.buffer, sizeof(TPMU_HA), &plen, NULL, pw_cbarg)) {
            TPM2_ERROR_raise(dctx->core, TPM2_ERR_AUTHORIZATION_FAILURE);
            goto error2;
        }
        userauth.size = plen;

        r = Esys_TR_SetAuth(dctx->esys_ctx, pkey->object, &userauth);
        TPM2_CHECK_RC(dctx->core, r, TPM2_ERR_CANNOT_LOAD_KEY, goto error2);
    }

    if ((keytype = tpm2_openssl_type(&pkey->data)) == NULL) {
        TPM2_ERROR_raise(dctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
        goto error2;
    }

    return keytype;
error2:
    if (pkey->data.privatetype == KEY_TYPE_HANDLE)
        Esys_TR_Close(pkey->esys_ctx, &pkey->object);
    else
        Esys_FlushContext(pkey->esys_ctx, pkey->object);
error1:
    pkey->object = ESYS_TR_NONE;
    return NULL;
}

static int
tpm2_tss2_decoder_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
                         int expected_type,
                         OSSL_CALLBACK *object_cb, void *object_cbarg,
                         OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    TPM2_TSS2_DECODER_CTX *dctx = ctx;
    TPM2_PKEY *pkey;
    BIO *bin;
    const char *keytype = NULL;
    OSSL_PARAM params[4];
    int fpos, object_type;
    int res = 0;

    DBG("TSS2 DECODER DECODE 0x%x\n", selection);
    if ((pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY))) == NULL)
        return 0;

    if ((bin = bio_new_from_core_bio(dctx->corebiometh, cin)) == NULL)
        goto error1;

    if ((fpos = BIO_tell(bin)) == -1)
        goto error2;

    pkey->core = dctx->core;
    pkey->esys_ctx = dctx->esys_ctx;
    pkey->capability = dctx->capability;
    pkey->object = ESYS_TR_NONE;

    if (selection == 0 || (selection & OSSL_KEYMGMT_SELECT_ALL) != 0)
        keytype = decode_privkey(dctx, pkey, bin, pw_cb, pw_cbarg);

    if (pkey->data.pub.publicArea.type == expected_type) {
        object_type = OSSL_OBJECT_PKEY;
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

        DBG("TSS2 DECODER DECODE found %s\n", keytype);
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
    } else {
        /* We return "empty handed". This is not an error. */
        res = 1;
    }
error2:
    BIO_free(bin);
error1:
    if (pkey->object != ESYS_TR_NONE) {
        if (pkey->data.privatetype == KEY_TYPE_HANDLE)
            Esys_TR_Close(pkey->esys_ctx, &pkey->object);
        else
            Esys_FlushContext(pkey->esys_ctx, pkey->object);
    }
    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
    return res;
}

static int
tpm2_tss2_decoder_decode_rsa(void *ctx, OSSL_CORE_BIO *cin, int selection,
                             OSSL_CALLBACK *object_cb, void *object_cbarg,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return tpm2_tss2_decoder_decode(ctx, cin, selection, TPM2_ALG_RSA,
                                    object_cb, object_cbarg, pw_cb, pw_cbarg);
}

static int
tpm2_tss2_decoder_decode_ec(void *ctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *object_cb, void *object_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return tpm2_tss2_decoder_decode(ctx, cin, selection, TPM2_ALG_ECC,
                                    object_cb, object_cbarg, pw_cb, pw_cbarg);
}

static int
tpm2_tss2_decoder_export_object(void *ctx, const void *objref, size_t objref_sz,
                                OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    TPM2_TSS2_DECODER_CTX *dctx = ctx;
    TPM2_PKEY *keydata;

    DBG("TSS2 DECODER EXPORT_OBJECT\n");
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

const OSSL_DISPATCH tpm2_tss_to_rsa_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_tss2_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_tss2_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_tss2_decoder_decode_rsa },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))tpm2_tss2_decoder_export_object },
    { 0, NULL }
};

const OSSL_DISPATCH tpm2_tss_to_ec_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_tss2_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_tss2_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_tss2_decoder_decode_ec },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))tpm2_tss2_decoder_export_object },
    { 0, NULL }
};

