/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <tss2/tss2_mu.h>

#include "tpm2-provider-pkey.h"
#include "tpm2-provider-types.h"

static const TPM2B_PUBLIC keyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = 0, /* set later */
        .parameters.eccDetail = {
             .curveID = 0, /* set later */
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .kdf = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
         },
        .unique.ecc = {
             .x.size = 0,
             .y.size = 0
         }
     }
};

typedef struct tpm2_ecgen_ctx_st TPM2_ECGEN_CTX;

struct tpm2_ecgen_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_CAPABILITY capability;
    TPM2_HANDLE parentHandle;
    TPM2B_DIGEST parentAuth;
    TPM2B_PUBLIC inPublic;
    TPM2B_SENSITIVE_CREATE inSensitive;
};

static OSSL_FUNC_keymgmt_new_fn tpm2_ec_keymgmt_new;
static OSSL_FUNC_keymgmt_gen_init_fn tpm2_ec_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn tpm2_ec_keymgmt_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn tpm2_ec_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn tpm2_ec_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn tpm2_ec_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn tpm2_ec_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn tpm2_ec_keymgmt_load;
static OSSL_FUNC_keymgmt_free_fn tpm2_ec_keymgmt_free;
static OSSL_FUNC_keymgmt_get_params_fn tpm2_ec_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn tpm2_ec_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_has_fn tpm2_ec_keymgmt_has;
static OSSL_FUNC_keymgmt_match_fn tpm2_ec_keymgmt_match;
static OSSL_FUNC_keymgmt_import_fn tpm2_ec_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn tpm2_ec_keymgmt_eximport_types;
OSSL_FUNC_keymgmt_export_fn tpm2_ec_keymgmt_export;

static void *
tpm2_ec_keymgmt_new(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_PKEY *pkey;

    DBG("EC NEW\n");
    if ((pkey = OPENSSL_zalloc(sizeof(TPM2_PKEY))) == NULL) {
        TPM2_ERROR_raise(cprov->core, TPM2_ERR_MEMORY_FAILURE);
        return NULL;
    }

    pkey->core = cprov->core;
    pkey->esys_ctx = cprov->esys_ctx;
    pkey->capability = cprov->capability;
    pkey->object = ESYS_TR_NONE;

    pkey->data.pub = keyTemplate;
    /* can be used in public key operations */
    pkey->data.pub.publicArea.objectAttributes =
            TPMA_OBJECT_SIGN_ENCRYPT;

    return pkey;
}

static void *
tpm2_ec_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_ECGEN_CTX *gen;

    DBG("EC GEN INIT %x\n", selection);
    if ((gen = OPENSSL_zalloc(sizeof(TPM2_ECGEN_CTX))) == NULL)
        return NULL;

    gen->core = cprov->core;
    gen->esys_ctx = cprov->esys_ctx;
    gen->capability = cprov->capability;

    gen->inPublic = keyTemplate;
    /* same default attributes as in tpm2_create */
    gen->inPublic.publicArea.objectAttributes =
            (TPMA_OBJECT_USERWITHAUTH |
             TPMA_OBJECT_SIGN_ENCRYPT |
             TPMA_OBJECT_DECRYPT |
             TPMA_OBJECT_FIXEDTPM |
             TPMA_OBJECT_FIXEDPARENT |
             TPMA_OBJECT_SENSITIVEDATAORIGIN);

    if (tpm2_ec_keymgmt_gen_set_params(gen, params))
        return gen;
    OPENSSL_clear_free(gen, sizeof(TPM2_ECGEN_CTX));
    return NULL;
}

static int
tpm2_ec_keymgmt_gen_set_template(void *ctx, void *templ)
{
    TPM2_ECGEN_CTX *gen = ctx;
    TPM2_PKEY *pkey = templ;

    DBG("EC GEN_SET_TEMPLATE\n");
    gen->inPublic.publicArea.parameters.eccDetail.curveID = TPM2_PKEY_EC_CURVE(pkey);

    return 1;
}

static int
tpm2_ec_keymgmt_gen_set_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_ECGEN_CTX *gen = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("EC GEN_SET_PARAMS", params);

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_PARENT);
    if (p != NULL && !OSSL_PARAM_get_uint32(p, &gen->parentHandle))
        return 0;

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_PARENT_AUTH);
    if (p != NULL && !tpm2_param_get_DIGEST(p, &gen->parentAuth))
        return 0;

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_USER_AUTH);
    if (p != NULL && !tpm2_param_get_DIGEST(p, &gen->inSensitive.sensitive.userAuth))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
                ((gen->inPublic.publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg =
                    tpm2_hash_name_to_alg(gen->capability.algorithms, p->data)) == TPM2_ALG_ERROR)) {
            TPM2_ERROR_raise(gen->core, TPM2_ERR_UNKNOWN_ALGORITHM);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
                ((gen->inPublic.publicArea.parameters.eccDetail.curveID =
                    tpm2_name_to_ecc_curve(p->data)) == TPM2_ECC_NONE)) {
            TPM2_ERROR_raise(gen->core, TPM2_ERR_UNKNOWN_ALGORITHM);
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *
tpm2_ec_keymgmt_gen_settable_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_uint32(TPM2_PKEY_PARAM_PARENT, NULL),
        OSSL_PARAM_utf8_string(TPM2_PKEY_PARAM_PARENT_AUTH, NULL, 0),
        OSSL_PARAM_utf8_string(TPM2_PKEY_PARAM_USER_AUTH, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DIGEST, NULL, 0),
        /* mandatory parameters used by openssl */
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static void *
tpm2_ec_keymgmt_gen(void *ctx, OSSL_CALLBACK *cb, void *cbarg)
{
    TPM2_ECGEN_CTX *gen = ctx;
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC *keyPublic = NULL;
    TPM2B_PRIVATE *keyPrivate = NULL;
    TPM2_PKEY *pkey = NULL;
    TSS2_RC r = TSS2_RC_SUCCESS;

    DBG("EC GEN%s\n",
        gen->inSensitive.sensitive.userAuth.size > 0 ? " with user-auth" : "");
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
        DBG("EC GEN parent: persistent 0x%x\n", gen->parentHandle);
        if (!tpm2_load_parent(pkey->core, pkey->esys_ctx,
                              gen->parentHandle, &gen->parentAuth, &parent))
            goto error1;
    } else {
        DBG("EC GEN parent: primary 0x%x\n", TPM2_RH_OWNER);
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
tpm2_ec_keymgmt_gen_cleanup(void *ctx)
{
    TPM2_ECGEN_CTX *gen = ctx;

    DBG("EC CLEANUP\n");
    if (gen == NULL)
        return;

    OPENSSL_clear_free(gen, sizeof(TPM2_ECGEN_CTX));
}

static void *
tpm2_ec_keymgmt_load(const void *reference, size_t reference_sz)
{
    TPM2_PKEY *pkey = NULL;

    DBG("EC LOAD\n");
    if (!reference || reference_sz != sizeof(pkey))
        return NULL;

    /* the contents of the reference is the address to our object */
    pkey = *(TPM2_PKEY **)reference;
    /* we grabbed it, so we detach it */
    *(TPM2_PKEY **)reference = NULL;

    return pkey;
}

static void
tpm2_ec_keymgmt_free(void *keydata)
{
    TPM2_PKEY *pkey = keydata;

    DBG("EC FREE\n");
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
tpm2_param_set_ecc_point(OSSL_PARAM *p,
                         const TPM2B_ECC_PARAMETER *x, const TPM2B_ECC_PARAMETER *y)
{
    size_t size;
    void *buffer;
    int res;

    if ((size = tpm2_ecc_point_to_uncompressed(x, y, &buffer)) == 0)
        return 0;
    res = OSSL_PARAM_set_octet_string(p, buffer, size);
    OPENSSL_free(buffer);
    return res;
}

static int
tpm2_ec_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    TPMS_ALGORITHM_DETAIL_ECC *details = NULL;
    OSSL_PARAM *p;
    TSS2_RC r;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("EC GET_PARAMS", params);

    r = Esys_ECC_Parameters(pkey->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM2_PKEY_EC_CURVE(pkey), &details);
    TPM2_CHECK_RC(pkey->core, r, TPM2_ERR_UNKNOWN_ALGORITHM, return 0);

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p,
            OBJ_nid2sn(tpm2_ecc_curve_to_nid(TPM2_PKEY_EC_CURVE(pkey)))))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, details->keySize))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int sec_bits;

        /* We apply the same logic as OpenSSL does */
        if (details->keySize >= 512)
            sec_bits = 256;
        else if (details->keySize >= 384)
            sec_bits = 192;
        else if (details->keySize >= 256)
            sec_bits = 128;
        else if (details->keySize >= 224)
            sec_bits = 112;
        else if (details->keySize >= 160)
            sec_bits = 80;
        else
            sec_bits = details->keySize / 2;

        if (!OSSL_PARAM_set_int(p, sec_bits))
            goto error;
    }
    /* reserve space for two uncompressed coordinates + initial byte */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE); /* max signature size */
    if (p != NULL && !OSSL_PARAM_set_int(p, tpm2_ecdsa_size(
                            tpm2_ecc_curve_to_nid(TPM2_PKEY_EC_CURVE(pkey)))))
        goto error;
    /* static curve parameters */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_P);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p, details->p))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_A);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p, details->a))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_B);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p, details->b))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_GENERATOR);
    if (p != NULL && !tpm2_param_set_ecc_point(p, &details->gX, &details->gY))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_ORDER);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p, details->n))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_COFACTOR);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p, details->h))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 0)) /* TPM supports named curves only */
        goto error;
    /* public key */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL && !tpm2_param_set_ecc_point(p, &pkey->data.pub.publicArea.unique.ecc.x,
                                                  &pkey->data.pub.publicArea.unique.ecc.y))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p, pkey->data.pub.publicArea.unique.ecc.x))
        goto error;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);
    if (p != NULL && !tpm2_param_set_BN_from_buffer(p, pkey->data.pub.publicArea.unique.ecc.y))
        goto error;
    free(details);
    return 1;
error:
    free(details);
    return 0;
}

static const OSSL_PARAM *
tpm2_ec_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        /* static curve parameters */
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
        /* public key */
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}

static const char *
tpm2_ec_keymgmt_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }
    return NULL;
}

static int
tpm2_ec_keymgmt_has(const void *keydata, int selection)
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    int ok = 1;

    DBG("EC HAS 0x%x\n", selection);
    if (pkey != NULL) {
        /* although not exportable we may have the the private portion */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (pkey->data.privatetype != KEY_TYPE_NONE);
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (pkey->data.pub.publicArea.unique.ecc.x.size > 0)
                    && (pkey->data.pub.publicArea.unique.ecc.y.size > 0);
        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
            ok = ok && (TPM2_PKEY_EC_CURVE(pkey) != 0);
    }
    return ok;
}

static int
tpm2_ec_keymgmt_match(const void *keydata1, const void *keydata2,
                       int selection)
{
    TPM2_PKEY *pkey1 = (TPM2_PKEY *)keydata1;
    TPM2_PKEY *pkey2 = (TPM2_PKEY *)keydata2;

    DBG("EC MATCH %x\n", selection);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            /* compare curve */
            if (TPM2_PKEY_EC_CURVE(pkey1) != TPM2_PKEY_EC_CURVE(pkey2))
                return 0;
            /* compare point */
            if (BUFFER_CMP(pkey1->data.pub.publicArea.unique.ecc.x,
                           pkey2->data.pub.publicArea.unique.ecc.x) ||
                BUFFER_CMP(pkey1->data.pub.publicArea.unique.ecc.y,
                           pkey2->data.pub.publicArea.unique.ecc.y))
                return 0;
        } else {
            /* we cannot compare private keys */
            return 0;
        }
    }

    return 1;
}

static int
tpm2_ec_keymgmt_import(void *keydata,
                       int selection, const OSSL_PARAM params[])
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    const OSSL_PARAM *p;

    if (pkey == NULL)
        return 0;
    TRACE_PARAMS("EC IMPORT", params);

    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_UTF8_STRING ||
                    ((TPM2_PKEY_EC_CURVE(pkey) =
                        tpm2_name_to_ecc_curve(p->data)) == TPM2_ECC_NONE)) {
                TPM2_ERROR_raise(pkey->core, TPM2_ERR_UNKNOWN_ALGORITHM);
                return 0;
            }
        }
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING ||
                    !tpm2_buffer_to_ecc_point(tpm2_ecc_curve_to_nid(TPM2_PKEY_EC_CURVE(pkey)),
                            p->data, p->data_size, &pkey->data.pub.publicArea.unique.ecc))
                return 0;
        }
    }

    return 1;
}

int
tpm2_ec_keymgmt_export(void *keydata, int selection,
                       OSSL_CALLBACK *param_cb, void *cbarg)
{
    TPM2_PKEY *pkey = (TPM2_PKEY *)keydata;
    int curve_nid;
    size_t pubsize;
    void *pubbuff = NULL;
    int ok = 0;

    DBG("EC EXPORT %x\n", selection);
    if (pkey == NULL)
        return 0;

    curve_nid = tpm2_ecc_curve_to_nid(TPM2_PKEY_EC_CURVE(pkey));

    pubsize = tpm2_ecc_point_to_uncompressed(
                &pkey->data.pub.publicArea.unique.ecc.x,
                &pkey->data.pub.publicArea.unique.ecc.y, &pubbuff);

    OSSL_PARAM params[3], *p = params;
    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)OBJ_nid2sn(curve_nid), 0);
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                 pubbuff, pubsize);
    *p = OSSL_PARAM_construct_end();

    ok = param_cb(params, cbarg);
    OPENSSL_free(pubbuff);
    return ok;
}

static const OSSL_PARAM *
tpm2_ec_keymgmt_eximport_types(int selection)
{
    static const OSSL_PARAM ecc_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return ecc_public_key_types;
    else
        return NULL;
}

const OSSL_DISPATCH tpm2_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void(*)(void))tpm2_ec_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void(*)(void))tpm2_ec_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void(*)(void))tpm2_ec_keymgmt_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void(*)(void))tpm2_ec_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void(*)(void))tpm2_ec_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void(*)(void))tpm2_ec_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void(*)(void))tpm2_ec_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void(*)(void))tpm2_ec_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void(*)(void))tpm2_ec_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))tpm2_ec_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))tpm2_ec_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void(*)(void))tpm2_ec_keymgmt_query_operation_name },
    { OSSL_FUNC_KEYMGMT_HAS, (void(*)(void))tpm2_ec_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))tpm2_ec_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void(*)(void))tpm2_ec_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void(*)(void))tpm2_ec_keymgmt_eximport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void(*)(void))tpm2_ec_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void(*)(void))tpm2_ec_keymgmt_eximport_types },
    { 0, NULL }
};

const OSSL_DISPATCH *tpm2_ec_keymgmt_dispatch(const TPM2_CAPABILITY *capability)
{
    if (tpm2_supports_algorithm(capability->algorithms, TPM2_ALG_ECC))
        return tpm2_ec_keymgmt_functions;
    else
        return NULL;
}

