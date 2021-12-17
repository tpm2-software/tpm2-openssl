/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>
#include <math.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <tss2/tss2_mu.h>

#include "tpm2-provider-pkey.h"
#include "tpm2-provider-types.h"

static const TPM2B_PUBLIC keyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = 0, /* set later */
        .authPolicy.size = 0,
        .parameters.rsaDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .keyBits = 2048, /* openssl default */
             .exponent = 0,
         },
        .unique.rsa.size = 0
     }
};

typedef struct tpm2_rsagen_ctx_st TPM2_RSAGEN_CTX;

struct tpm2_rsagen_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_CAPABILITY capability;
    TPM2_HANDLE parentHandle;
    TPM2B_DIGEST parentAuth;
    TPM2B_PUBLIC inPublic;
    TPM2B_SENSITIVE_CREATE inSensitive;
    int scheme_locked;
};

static OSSL_FUNC_keymgmt_new_fn tpm2_rsa_keymgmt_new;
static OSSL_FUNC_keymgmt_gen_init_fn tpm2_rsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn tpm2_rsapss_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn tpm2_rsa_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn tpm2_rsa_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn tpm2_rsa_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn tpm2_rsa_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn tpm2_rsa_keymgmt_load;
static OSSL_FUNC_keymgmt_free_fn tpm2_rsa_keymgmt_free;
static OSSL_FUNC_keymgmt_get_params_fn tpm2_rsa_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn tpm2_rsa_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_query_operation_name_fn tpm2_rsa_keymgmt_query_operation_name;
static OSSL_FUNC_keymgmt_has_fn tpm2_rsa_keymgmt_has;
static OSSL_FUNC_keymgmt_match_fn tpm2_rsa_keymgmt_match;
static OSSL_FUNC_keymgmt_import_fn tpm2_rsa_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn tpm2_rsa_keymgmt_eximport_types;
OSSL_FUNC_keymgmt_export_fn tpm2_rsa_keymgmt_export;

static void *
tpm2_rsa_keymgmt_new(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_PKEY *pkey;

    DBG("RSA NEW\n");
    if ((pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY))) == NULL) {
        TPM2_ERROR_raise(cprov->core, TPM2_ERR_MEMORY_FAILURE);
        return NULL;
    }

    pkey->core = cprov->core;
    pkey->esys_ctx = cprov->esys_ctx;
    pkey->capability = cprov->capability;
    pkey->object = ESYS_TR_NONE;

    pkey->data.pub = keyTemplate;
    pkey->data.pub.publicArea.objectAttributes =
            TPMA_OBJECT_SIGN_ENCRYPT;

    return pkey;
}

static TPM2_RSAGEN_CTX *
tpm2_create_rsagen_ctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSAGEN_CTX *gen;

    if ((gen = OPENSSL_zalloc(sizeof(TPM2_RSAGEN_CTX))) == NULL)
        return NULL;

    gen->core = cprov->core;
    gen->esys_ctx = cprov->esys_ctx;
    gen->capability = cprov->capability;
    return gen;
}

static void *
tpm2_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    TPM2_RSAGEN_CTX *gen;

    DBG("RSA GEN INIT rsa %x\n", selection);
    if ((gen = tpm2_create_rsagen_ctx(provctx)) == NULL)
        return NULL;

    gen->inPublic = keyTemplate;
    /* same default attributes as in tpm2_create */
    gen->inPublic.publicArea.objectAttributes =
            (TPMA_OBJECT_USERWITHAUTH |
             TPMA_OBJECT_SIGN_ENCRYPT |
             /* a non-restricted key may also decrypt */
             TPMA_OBJECT_DECRYPT |
             TPMA_OBJECT_FIXEDTPM |
             TPMA_OBJECT_FIXEDPARENT |
             TPMA_OBJECT_SENSITIVEDATAORIGIN);

    if (tpm2_rsa_keymgmt_gen_set_params(gen, params))
        return gen;
    OPENSSL_clear_free(gen, sizeof(TPM2_RSAGEN_CTX));
    return NULL;
}

static void *
tpm2_rsapss_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    TPM2_RSAGEN_CTX *gen;

    DBG("RSA GEN INIT rsapss %x\n", selection);
    if ((gen = tpm2_create_rsagen_ctx(provctx)) == NULL)
        return NULL;

    gen->inPublic = keyTemplate;
    /* same default attributes as in tpm2_create */
    gen->inPublic.publicArea.objectAttributes =
            /* a RSA-PSS key is restricted to RSA-PSS scheme */
            (TPMA_OBJECT_RESTRICTED |
             TPMA_OBJECT_USERWITHAUTH |
             TPMA_OBJECT_SIGN_ENCRYPT |
             TPMA_OBJECT_FIXEDTPM |
             TPMA_OBJECT_FIXEDPARENT |
             TPMA_OBJECT_SENSITIVEDATAORIGIN);

    gen->inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSAPSS;
    gen->scheme_locked = 1;

    if (tpm2_rsa_keymgmt_gen_set_params(gen, params))
        return gen;
    OPENSSL_clear_free(gen, sizeof(TPM2_RSAGEN_CTX));
    return NULL;
}

static int
tpm2_rsa_keymgmt_gen_set_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_RSAGEN_CTX *gen = ctx;
    const OSSL_PARAM *p;
    size_t bits, primes;
    BIGNUM *e = NULL;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("RSA GEN_SET_PARAMS", params);

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_PARENT);
    if (p != NULL && !OSSL_PARAM_get_uint32(p, &gen->parentHandle))
        return 0;

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_PARENT_AUTH);
    if (p != NULL && !tpm2_param_get_DIGEST(p, &gen->parentAuth))
        return 0;

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_USER_AUTH);
    if (p != NULL && !tpm2_param_get_DIGEST(p, &gen->inSensitive.sensitive.userAuth))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
                ((gen->inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
                    tpm2_hash_name_to_alg(gen->capability.algorithms, p->data)) == TPM2_ALG_ERROR)) {
            TPM2_ERROR_raise(gen->core, TPM2_ERR_UNKNOWN_ALGORITHM);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &bits))
            return 0;
        gen->inPublic.publicArea.parameters.rsaDetail.keyBits = bits;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES);
    /* TCG: TPM supports only public keys that are the product of two primes */
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &primes) || primes != 2))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL) {
        if (!OSSL_PARAM_get_BN(p, &e))
            return 0;
        gen->inPublic.publicArea.parameters.rsaDetail.exponent = BN_get_word(e);
        BN_free(e);
    }

    return 1;
}

static const OSSL_PARAM *
tpm2_rsa_keymgmt_gen_settable_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_uint32(TPM2_PKEY_PARAM_PARENT, NULL),
        OSSL_PARAM_utf8_string(TPM2_PKEY_PARAM_PARENT_AUTH, NULL, 0),
        OSSL_PARAM_utf8_string(TPM2_PKEY_PARAM_USER_AUTH, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
        /* mandatory parameters used by openssl */
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static void *
tpm2_rsa_keymgmt_gen(void *ctx, OSSL_CALLBACK *cb, void *cbarg)
{
    TPM2_RSAGEN_CTX *gen = ctx;
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC *keyPublic = NULL;
    TPM2B_PRIVATE *keyPrivate = NULL;
    TPM2_PKEY *pkey = NULL;
    TSS2_RC r = TSS2_RC_SUCCESS;

    DBG("RSA GEN%s %i bits\n",
        gen->inSensitive.sensitive.userAuth.size > 0 ? " with user-auth" : "",
        gen->inPublic.publicArea.parameters.rsaDetail.keyBits);
    pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY));
    if (pkey == NULL) {
        TPM2_ERROR_raise(gen->core, TPM2_ERR_MEMORY_FAILURE);
        return NULL;
    }

    pkey->core = gen->core;
    pkey->esys_ctx = gen->esys_ctx;
    pkey->capability = gen->capability;

    if (gen->inSensitive.sensitive.userAuth.size == 0)
        pkey->data.emptyAuth = 1;

    pkey->data.parent = gen->parentHandle;
    /* load parent */
    if (gen->parentHandle && gen->parentHandle != TPM2_RH_OWNER) {
        DBG("RSA GEN parent: persistent 0x%x\n", gen->parentHandle);
        if (!tpm2_load_parent(pkey->core, pkey->esys_ctx,
                              gen->parentHandle, &gen->parentAuth, &parent))
            goto error1;
    } else {
        DBG("RSA GEN parent: primary 0x%x\n", TPM2_RH_OWNER);
        if (!tpm2_build_primary(pkey->core, pkey->esys_ctx, pkey->capability.algorithms,
                                ESYS_TR_RH_OWNER, &gen->parentAuth, &parent))
            goto error1;
    }

    size_t offset = 0;
    TPM2B_TEMPLATE template = { .size = 0 };
    r = Tss2_MU_TPMT_PUBLIC_Marshal(&gen->inPublic.publicArea,
                                    template.buffer, sizeof(TPMT_PUBLIC), &offset);
    TPM2_CHECK_RC(gen->core, r, TPM2_ERR_INPUT_CORRUPTED, goto final);
    template.size = offset;

    r = Esys_CreateLoaded(gen->esys_ctx, parent,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &gen->inSensitive, &template,
                          &pkey->object, &keyPrivate, &keyPublic);
    TPM2_CHECK_RC(gen->core, r, TPM2_ERR_CANNOT_CREATE_KEY, goto final);

    pkey->data.pub = *keyPublic;
    free(keyPublic);
    pkey->data.privatetype = KEY_TYPE_BLOB;
    pkey->data.priv = *keyPrivate;
    free(keyPrivate);

final:
    if (gen->parentHandle && gen->parentHandle != TPM2_RH_OWNER)
        Esys_TR_Close(gen->esys_ctx, &parent);
    else
        Esys_FlushContext(gen->esys_ctx, parent);

    if (r == TSS2_RC_SUCCESS)
        return pkey;
error1:
    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
    return NULL;
}

static void
tpm2_rsa_keymgmt_gen_cleanup(void *ctx)
{
    TPM2_RSAGEN_CTX *gen = ctx;

    DBG("RSA CLEANUP\n");
    if (gen == NULL)
        return;

    OPENSSL_clear_free(gen, sizeof(TPM2_RSAGEN_CTX));
}

static void *
tpm2_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    TPM2_PKEY *pkey = NULL;

    DBG("RSA LOAD\n");
    if (!reference || reference_sz != sizeof(pkey))
        return NULL;

    /* the contents of the reference is the address to our object */
    pkey = *(TPM2_PKEY **)reference;
    /* we grabbed it, so we detach it */
    *(TPM2_PKEY **)reference = NULL;

    return pkey;
}

static void
tpm2_rsa_keymgmt_free(void *keydata)
{
    TPM2_PKEY *pkey = keydata;

    DBG("RSA FREE\n");
    if (pkey == NULL)
        return;

    if (pkey->object != ESYS_TR_NONE) {
        if (pkey->data.privatetype == KEY_TYPE_HANDLE)
            Esys_TR_Close(pkey->esys_ctx, &pkey->object);
        else
            Esys_FlushContext(pkey->esys_ctx, pkey->object);
    }

    OPENSSL_clear_free(pkey, sizeof(TPM2_PKEY));
}

static int
tpm2_rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("RSA GET_PARAMS", params);

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, TPM2_PKEY_RSA_BITS(pkey)))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        /*
         * NIST SP 800-56B rev 2 Appendix D: Maximum Security Strength
         * Estimates for IFC Modulus Lengths.
         *
         * E = \frac{1.923 \sqrt[3]{nBits \cdot log_e(2)}
         *           \cdot(log_e(nBits \cdot log_e(2))^{2/3} - 4.69}{log_e(2)}
         */

        double nBits = TPM2_PKEY_RSA_BITS(pkey);
        double log_2 = log(2.0);
        double e =
            ( 1.923
              * cbrt(nBits * log_2)
              * cbrt(pow(log(nBits * log_2), 2.0))
              - 4.69 )
            / log_2;

        if (!OSSL_PARAM_set_int(p, (int)e))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, TPM2_MAX_RSA_KEY_BYTES))
        return 0;

    if (TPM2_PKEY_RSA_SCHEME(pkey) != TPM2_ALG_NULL) {
        /* if the key is associated with a hash, it is mandatory */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p,
                (char *)tpm2_hash_alg_to_name(TPM2_PKEY_RSA_HASH(pkey))))
            return 0;
    }

    /* public key */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p,
                            pkey->data.pub.publicArea.unique.rsa))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL && !tpm2_param_set_BN_from_uint32(p,
                            pkey->data.pub.publicArea.parameters.rsaDetail.exponent))
        return 0;

    return 1;
}

static const OSSL_PARAM *
tpm2_rsa_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        /* public key */
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}

static const char *
tpm2_rsa_keymgmt_query_operation_name(int operation_id)
{
    /* For any RSA key, we use the "RSA" algorithms regardless of sub-type. */
    return "RSA";
}

static int
tpm2_rsa_keymgmt_has(const void *keydata, int selection)
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    int ok = 1;

    DBG("RSA HAS %x\n", selection);
    if (pkey != NULL) {
        /* although not exportable we may have the the private portion */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (pkey->data.privatetype != KEY_TYPE_NONE);
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (pkey->data.pub.publicArea.unique.rsa.size > 0);
    }
    return ok;
}

static UINT32
pkey_get_rsa_exp(const TPM2_PKEY *pkey)
{
    UINT32 exponent;

    exponent = pkey->data.pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;

    return exponent;
}

static int
tpm2_rsa_keymgmt_match(const void *keydata1, const void *keydata2,
                       int selection)
{
    TPM2_PKEY *pkey1 = (TPM2_PKEY *)keydata1;
    TPM2_PKEY *pkey2 = (TPM2_PKEY *)keydata2;

    DBG("RSA MATCH 0x%x\n", selection);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            /* compare N */
            if (BUFFER_CMP(pkey1->data.pub.publicArea.unique.rsa,
                           pkey2->data.pub.publicArea.unique.rsa))
                return 0;
            /* compare E */
            if (pkey_get_rsa_exp(pkey1) != pkey_get_rsa_exp(pkey2))
                return 0;
        } else {
            /* we cannot compare private keys */
            return 0;
        }
    }

    return 1;
}

static int
tpm2_rsa_keymgmt_import(void *keydata,
                        int selection, const OSSL_PARAM params[])
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    const OSSL_PARAM *p;

    if (pkey == NULL)
        return 0;
    TRACE_PARAMS("RSA IMPORT", params);

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
        if (p != NULL) {
            BIGNUM *bignum = NULL;
            int tolen;

            if (!OSSL_PARAM_get_BN(p, &bignum))
                return 0;

            pkey->data.pub.publicArea.parameters.rsaDetail.keyBits = BN_num_bits(bignum);

            tolen = BN_bn2bin(bignum, pkey->data.pub.publicArea.unique.rsa.buffer);
            BN_free(bignum);
            if (tolen < 0)
                return 0;

            pkey->data.pub.publicArea.unique.rsa.size = tolen;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
        if (p != NULL && !OSSL_PARAM_get_uint32(p,
                    &pkey->data.pub.publicArea.parameters.rsaDetail.exponent))
            return 0;
    }

    return 1;
}

int
tpm2_rsa_keymgmt_export(void *keydata, int selection,
                        OSSL_CALLBACK *param_cb, void *cbarg)
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    UINT32 exponent;
    int ok = 1;

    DBG("RSA EXPORT %x\n", selection);
    if (pkey == NULL)
        return 0;

    OSSL_PARAM params[3], *p = params;
#if !defined(WORDS_BIGENDIAN)
    unsigned char *n = NULL;
#endif
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
#if defined(WORDS_BIGENDIAN)
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                       pkey->data.pub.publicArea.unique.rsa.buffer,
                                       pkey->data.pub.publicArea.unique.rsa.size);
#else
        n = OPENSSL_malloc(pkey->data.pub.publicArea.unique.rsa.size);
        /* just reverse the bytes; the BN export/import is unnecessarily complex */
        revmemcpy(n, pkey->data.pub.publicArea.unique.rsa.buffer,
                  pkey->data.pub.publicArea.unique.rsa.size);
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                       n, pkey->data.pub.publicArea.unique.rsa.size);
#endif
        exponent = pkey_get_rsa_exp(pkey);
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                     (unsigned char *)&exponent, sizeof(exponent));
    }
    *p = OSSL_PARAM_construct_end();

    ok = param_cb(params, cbarg);

#if !defined(WORDS_BIGENDIAN)
    OPENSSL_free(n);
#endif
    return ok;
}

static const OSSL_PARAM *
tpm2_rsa_keymgmt_eximport_types(int selection)
{
    static const OSSL_PARAM rsa_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return rsa_public_key_types;
    else
        return NULL;
}

#define DECLARE_KEYMGMT_FUNCTIONS(type) \
    const OSSL_DISPATCH tpm2_##type##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void(*)(void))tpm2_rsa_keymgmt_new }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void(*)(void))tpm2_##type##_keymgmt_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void(*)(void))tpm2_rsa_keymgmt_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void(*)(void))tpm2_rsa_keymgmt_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void(*)(void))tpm2_rsa_keymgmt_load }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void(*)(void))tpm2_rsa_keymgmt_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))tpm2_rsa_keymgmt_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void(*)(void))tpm2_rsa_keymgmt_query_operation_name }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void(*)(void))tpm2_rsa_keymgmt_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))tpm2_rsa_keymgmt_match }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void(*)(void))tpm2_rsa_keymgmt_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void(*)(void))tpm2_rsa_keymgmt_eximport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void(*)(void))tpm2_rsa_keymgmt_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void(*)(void))tpm2_rsa_keymgmt_eximport_types }, \
        { 0, NULL } \
    };

DECLARE_KEYMGMT_FUNCTIONS(rsa)
DECLARE_KEYMGMT_FUNCTIONS(rsapss)

const OSSL_DISPATCH *tpm2_rsa_keymgmt_dispatch(const TPM2_CAPABILITY *capability)
{
    if (tpm2_supports_algorithm(capability->algorithms, TPM2_ALG_RSA))
        return tpm2_rsa_keymgmt_functions;
    else
        return NULL;
}

const OSSL_DISPATCH *tpm2_rsapss_keymgmt_dispatch(const TPM2_CAPABILITY *capability)
{
    if (tpm2_supports_algorithm(capability->algorithms, TPM2_ALG_RSA)
            && tpm2_supports_algorithm(capability->algorithms, TPM2_ALG_RSAPSS))
        return tpm2_rsapss_keymgmt_functions;
    else
        return NULL;
}

