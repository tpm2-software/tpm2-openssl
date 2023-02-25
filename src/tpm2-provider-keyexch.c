/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>

#include "tpm2-provider.h"
#include "tpm2-provider-types.h"

typedef struct tpm2_keyexch_ctx_st TPM2_KEYEXCH_CTX;

struct tpm2_keyexch_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
    ESYS_CONTEXT *esys_ctx;
    TPM2_PKEY *pkey;
    TPM2B_ECC_POINT peer;
    /* KDF settings */
    char kdf_name[TPM2_MAX_OSSL_NAME];
    char kdf_hash[TPM2_MAX_OSSL_NAME];
    char *kdf_propq;
    size_t kdf_outlen;
    void *kdf_ukmptr;
    size_t kdf_ukmlen;
};

static OSSL_FUNC_keyexch_newctx_fn tpm2_keyexch_newctx;
static OSSL_FUNC_keyexch_init_fn tpm2_keyexch_init;
static OSSL_FUNC_keyexch_set_peer_fn tpm2_keyexch_set_peer;
static OSSL_FUNC_keyexch_derive_fn tpm2_keyexch_derive;
static OSSL_FUNC_keyexch_freectx_fn tpm2_keyexch_freectx;
static OSSL_FUNC_keyexch_set_ctx_params_fn tpm2_keyexch_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn tpm2_keyexch_settable_ctx_params;

static void *
tpm2_keyexch_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_KEYEXCH_CTX *kexc = OPENSSL_zalloc(sizeof(TPM2_KEYEXCH_CTX));

    DBG("KEYEXCH NEW\n");
    if (kexc == NULL)
        return NULL;

    kexc->core = cprov->core;
    kexc->libctx = cprov->libctx;
    kexc->esys_ctx = cprov->esys_ctx;
    return kexc;
}

static void
tpm2_keyexch_freectx(void *ctx)
{
    TPM2_KEYEXCH_CTX *kexc = ctx;

    DBG("KEYEXCH FREE\n");
    if (kexc == NULL)
        return;

    OPENSSL_free(kexc->kdf_propq);
    OPENSSL_clear_free(kexc->kdf_ukmptr, kexc->kdf_ukmlen);
    OPENSSL_clear_free(kexc, sizeof(TPM2_KEYEXCH_CTX));
}

static int
tpm2_keyexch_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    TPM2_KEYEXCH_CTX *kexc = ctx;

    DBG("KEYEXCH INIT\n");
    kexc->pkey = provkey;

    return tpm2_keyexch_set_ctx_params(kexc, params);
}

static int
tpm2_keyexch_set_peer(void *ctx, void *provkey)
{
    TPM2_KEYEXCH_CTX *kexc = ctx;
    TPM2_PKEY *peerkey = provkey;

    DBG("KEYEXCH SET_PEER\n");
    kexc->peer.point = peerkey->data.pub.publicArea.unique.ecc;
    return 1;
}

static int
tpm2_keyexch_derive_kdf(TPM2_KEYEXCH_CTX *kexc, unsigned char *secret,
                        size_t *secretlen, size_t outlen)
{
    TPM2B_ECC_POINT *outPoint = NULL;
    TSS2_RC r;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;
    int res = 0;

    if (secret == NULL) {
        *secretlen = kexc->kdf_outlen;
        return 1;
    } else
        DBG("KEYEXCH DERIVE %s %s\n", kexc->kdf_name, kexc->kdf_hash);

    if (kexc->kdf_outlen > outlen) {
        TPM2_ERROR_raise(kexc->core, TPM2_ERR_WRONG_DATA_LENGTH);
        return 0;
    }

    r = Esys_ECDH_ZGen(kexc->esys_ctx, kexc->pkey->object,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                       &kexc->peer, &outPoint);
    TPM2_CHECK_RC(kexc->core, r, TPM2_ERR_CANNOT_GENERATE, return 0);

    if ((kdf = EVP_KDF_fetch(kexc->libctx, kexc->kdf_name, kexc->kdf_propq)) == NULL
            || (kctx = EVP_KDF_CTX_new(kdf)) == NULL)
        goto error;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                kexc->kdf_hash, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                outPoint->point.x.buffer, outPoint->point.x.size);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                kexc->kdf_ukmptr, kexc->kdf_ukmlen);
    *p = OSSL_PARAM_construct_end();

    res = EVP_KDF_derive(kctx, secret, outlen, params) > 0;
    *secretlen = kexc->kdf_outlen;

error:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    free(outPoint);
    return res;
}

static int
tpm2_keyexch_derive_plain(TPM2_KEYEXCH_CTX *kexc, unsigned char *secret,
                          size_t *secretlen, size_t outlen)
{
    TPM2B_ECC_POINT *outPoint = NULL;
    TSS2_RC r;

    DBG("KEYEXCH DERIVE plain\n");

    r = Esys_ECDH_ZGen(kexc->esys_ctx, kexc->pkey->object,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                       &kexc->peer, &outPoint);
    TPM2_CHECK_RC(kexc->core, r, TPM2_ERR_CANNOT_GENERATE, return 0);

    /* shared value is the x-coordinate */
    *secretlen = outPoint->point.x.size;
    if (secret != NULL) {
        if (*secretlen > outlen) {
            free(outPoint);
            return 0;
        }
        memcpy(secret, outPoint->point.x.buffer, *secretlen);
    }

    free(outPoint);
    return 1;
}

static int
tpm2_keyexch_derive(void *ctx, unsigned char *secret, size_t *secretlen,
                    size_t outlen)
{
    TPM2_KEYEXCH_CTX *kexc = ctx;

    if (kexc->kdf_name[0])
        return tpm2_keyexch_derive_kdf(kexc, secret, secretlen, outlen);
    else
        return tpm2_keyexch_derive_plain(kexc, secret, secretlen, outlen);
}

static int
tpm2_keyexch_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_KEYEXCH_CTX *kexc = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("KEYEXCH SET_CTX_PARAMS", params);

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        char *pname = kexc->kdf_name;
        if (!OSSL_PARAM_get_utf8_string(p, &pname, TPM2_MAX_OSSL_NAME))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL) {
        char *pname = kexc->kdf_hash;
        if (!OSSL_PARAM_get_utf8_string(p, &pname, TPM2_MAX_OSSL_NAME))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
    if (p != NULL) {
        OPENSSL_free(kexc->kdf_propq);
        kexc->kdf_propq = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &kexc->kdf_propq, 0))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &kexc->kdf_outlen))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL) {
        OPENSSL_clear_free(kexc->kdf_ukmptr, kexc->kdf_ukmlen);
        kexc->kdf_ukmptr = NULL;

        if (!OSSL_PARAM_get_octet_string(p, &kexc->kdf_ukmptr, 0, &kexc->kdf_ukmlen))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *
tpm2_keyexch_settable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

const OSSL_DISPATCH tpm2_ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void(*)(void))tpm2_keyexch_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void(*)(void))tpm2_keyexch_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void(*)(void))tpm2_keyexch_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void(*)(void))tpm2_keyexch_derive },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void(*)(void))tpm2_keyexch_freectx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void(*)(void))tpm2_keyexch_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_keyexch_settable_ctx_params },
    { 0, NULL }
};

