/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include "tpm2-provider.h"
#include "tpm2-provider-types.h"

typedef struct tpm2_keyexch_ctx_st TPM2_KEYEXCH_CTX;

struct tpm2_keyexch_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_PKEY *pkey;
    TPM2B_ECC_POINT peer;
};

static OSSL_FUNC_keyexch_newctx_fn tpm2_keyexch_newctx;
static OSSL_FUNC_keyexch_init_fn tpm2_keyexch_init;
static OSSL_FUNC_keyexch_set_peer_fn tpm2_keyexch_set_peer;
static OSSL_FUNC_keyexch_derive_fn tpm2_keyexch_derive;
static OSSL_FUNC_keyexch_freectx_fn tpm2_keyexch_freectx;

static void *
tpm2_keyexch_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_KEYEXCH_CTX *kexc = OPENSSL_zalloc(sizeof(TPM2_KEYEXCH_CTX));

    DBG("KEYEXCH NEW\n");
    if (kexc == NULL)
        return NULL;

    kexc->core = cprov->core;
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

    OPENSSL_clear_free(kexc, sizeof(TPM2_KEYEXCH_CTX));
}

static int
tpm2_keyexch_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    TPM2_KEYEXCH_CTX *kexc = ctx;

    DBG("KEYEXCH INIT\n");
    kexc->pkey = provkey;
    return 1;
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
tpm2_keyexch_derive(void *ctx, unsigned char *secret, size_t *secretlen,
                    size_t outlen)
{
    TPM2_KEYEXCH_CTX *kexc = ctx;
    TPM2B_ECC_POINT *outPoint = NULL;
    TSS2_RC r;

    DBG("KEYEXCH DERIVE\n");

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

const OSSL_DISPATCH tpm2_ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void(*)(void))tpm2_keyexch_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void(*)(void))tpm2_keyexch_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void(*)(void))tpm2_keyexch_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void(*)(void))tpm2_keyexch_derive },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void(*)(void))tpm2_keyexch_freectx },
    { 0, NULL }
};

