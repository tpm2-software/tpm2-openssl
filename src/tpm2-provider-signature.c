/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"
#include "tpm2-provider-types.h"
#include "tpm2-provider-x509.h"

typedef struct tpm2_signature_ctx_st TPM2_SIGNATURE_CTX;

struct tpm2_signature_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_PKEY *pkey;
    TPMT_SIG_SCHEME signScheme;
    TPM2_ALG_ID digalg;
    ESYS_TR sequenceHandle;
    TPMT_SIGNATURE *signature;
};

static OSSL_FUNC_signature_newctx_fn tpm2_signature_newctx;
static OSSL_FUNC_signature_freectx_fn tpm2_signature_freectx;
static OSSL_FUNC_signature_sign_init_fn tpm2_rsa_signature_sign_init;
static OSSL_FUNC_signature_sign_init_fn tpm2_ecdsa_signature_sign_init;
static OSSL_FUNC_signature_sign_fn tpm2_signature_sign;
static OSSL_FUNC_signature_digest_sign_init_fn tpm2_signature_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn tpm2_signature_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn tpm2_signature_digest_sign_final;
static OSSL_FUNC_signature_digest_sign_fn tpm2_signature_digest_sign;
static OSSL_FUNC_signature_get_ctx_params_fn tpm2_signature_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn tpm2_signature_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn tpm2_rsa_signature_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn tpm2_rsa_signature_settable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn tpm2_ecdsa_signature_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn tpm2_ecdsa_signature_settable_ctx_params;

static void *
tpm2_signature_newctx(void *provctx, const char *propq)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_SIGNATURE_CTX *sctx = OPENSSL_zalloc(sizeof(TPM2_SIGNATURE_CTX));

    if (sctx == NULL)
        return NULL;

    sctx->core = cprov->core;
    sctx->esys_ctx = cprov->esys_ctx;
    sctx->signScheme.scheme = TPM2_ALG_NULL;
    sctx->signScheme.details.any.hashAlg = TPM2_ALG_NULL;
    sctx->digalg = TPM2_ALG_NULL;
    sctx->sequenceHandle = ESYS_TR_NONE;
    return sctx;
}

static void
tpm2_signature_freectx(void *ctx)
{
    TPM2_SIGNATURE_CTX *sctx = ctx;

    if (sctx == NULL)
        return;

    free(sctx->signature);
    OPENSSL_clear_free(sctx, sizeof(TPM2_SIGNATURE_CTX));
}

static int
rsa_signature_scheme_init(TPM2_SIGNATURE_CTX *sctx, const char *mdname)
{
    /* determine hash algorithm */
    if (mdname == NULL) {
        if (sctx->signScheme.details.any.hashAlg != TPM2_ALG_NULL)
            /* hash algorithm was specified in SET_CTX_PARAMS */
            sctx->digalg = sctx->signScheme.details.any.hashAlg;
        else if (TPM2_PKEY_RSA_SCHEME(sctx->pkey) != TPM2_ALG_NULL)
            /* hash algorithm is associated with the key */
            sctx->digalg = TPM2_PKEY_RSA_HASH(sctx->pkey);
        else
            sctx->digalg = TPM2_ALG_SHA256;
    } else if ((sctx->digalg = tpm2_hash_name_to_alg(mdname)) == TPM2_ALG_ERROR) {
        TPM2_ERROR_raise(sctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
        return 0;
    }

    if (sctx->signScheme.scheme == TPM2_ALG_NULL) {
        if (TPM2_PKEY_RSA_SCHEME(sctx->pkey) != TPM2_ALG_NULL)
            /* copy the key algorithm for ALGORITHM_ID calculation */
            sctx->signScheme.scheme = TPM2_PKEY_RSA_SCHEME(sctx->pkey);
        else
            /* no signing scheme was defined, use default */
            sctx->signScheme.scheme = TPM2_ALG_RSASSA;
    }

    if (sctx->signScheme.details.any.hashAlg == TPM2_ALG_NULL)
        sctx->signScheme.details.any.hashAlg = sctx->digalg;

    return 1;
}

static int
ecdsa_signature_scheme_init(TPM2_SIGNATURE_CTX *sctx, const char *mdname)
{
    /* determine hash algorithm */
    if (mdname == NULL) {
        if (sctx->signScheme.details.any.hashAlg != TPM2_ALG_NULL)
            /* hash algorithm was specified in SET_CTX_PARAMS */
            sctx->digalg = sctx->signScheme.details.any.hashAlg;
        else if (TPM2_PKEY_RSA_SCHEME(sctx->pkey) != TPM2_ALG_NULL)
            /* hash algorithm is associated with the key */
            sctx->digalg = TPM2_PKEY_RSA_HASH(sctx->pkey);
        else
            sctx->digalg = TPM2_ALG_SHA256;
    } else if ((sctx->digalg = tpm2_hash_name_to_alg(mdname)) == TPM2_ALG_ERROR) {
        TPM2_ERROR_raise(sctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
        return 0;
    }

    if (sctx->signScheme.scheme == TPM2_ALG_NULL)
        sctx->signScheme.scheme = TPM2_ALG_ECDSA;

    if (sctx->signScheme.details.any.hashAlg == TPM2_ALG_NULL)
        sctx->signScheme.details.any.hashAlg = sctx->digalg;

    return 1;
}

static int
tpm2_rsa_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    TPM2_SIGNATURE_CTX *sctx = ctx;

    DBG("SIGN SIGN_INIT rsa\n");
    sctx->pkey = provkey;

    return (tpm2_rsa_signature_set_ctx_params(sctx, params)
        && rsa_signature_scheme_init(sctx, NULL));
}

static int
tpm2_ecdsa_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    TPM2_SIGNATURE_CTX *sctx = ctx;

    DBG("SIGN SIGN_INIT ecdsa\n");
    sctx->pkey = provkey;

    return (tpm2_ecdsa_signature_set_ctx_params(sctx, params)
        && ecdsa_signature_scheme_init(sctx, NULL));
}

static int
estimate_signature_size(const TPMT_PUBLIC *public)
{
    if (public->type == TPM2_ALG_RSA) {
        return (public->parameters.rsaDetail.keyBits + 7) / 8;
    } else if (public->type == TPM2_ALG_ECC) {
        return tpm2_ecdsa_size(tpm2_ecc_curve_to_nid(public->parameters.eccDetail.curveID));
    }
    else
        return 0;
}

static int
encode_ecdsa_sig(const TPMS_SIGNATURE_ECC *sig, unsigned char **str)
{
    ECDSA_SIG *data = NULL;
    int res = 0;

    if ((data = ECDSA_SIG_new()) != NULL &&
            ECDSA_SIG_set0(data, BN_bin2bn(sig->signatureR.buffer,
                                           sig->signatureR.size, NULL),
                                 BN_bin2bn(sig->signatureS.buffer,
                                           sig->signatureS.size, NULL)))
        res = i2d_ECDSA_SIG(data, str);

    ECDSA_SIG_free(data);
    return res;
}

static int
get_signature_buffer(const TPMT_SIGNATURE *signature,
                     unsigned char *sig, size_t *siglen, size_t sigsize)
{
    if (signature->sigAlg == TPM2_ALG_RSASSA ||
            signature->sigAlg == TPM2_ALG_RSAPSS) {
        /* copy buffer */
        *siglen = signature->signature.rsassa.sig.size;
        if (sig != NULL) {
            if (*siglen > sigsize)
                return 0;
            memcpy(sig, signature->signature.rsassa.sig.buffer, *siglen);
        }
        return 1;
    } else if (signature->sigAlg == TPM2_ALG_ECDSA) {
        int strlen;
        unsigned char *str = NULL;

        if ((strlen = encode_ecdsa_sig(&signature->signature.ecdsa, &str)) < 0)
            return 0;
        *siglen = strlen;
        if (sig != NULL) {
            if (*siglen > sigsize) {
                free(str);
                return 0;
            }
            memcpy(sig, str, *siglen);
        }
        free(str);
        return 1;
    } else
        return 0;
}

static int
tpm2_signature_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                    const unsigned char *tbs, size_t tbslen)
{
    TPM2_SIGNATURE_CTX *sctx = ctx;
    TPM2B_DIGEST digest;
    TSS2_RC r;

    TPMT_TK_HASHCHECK empty_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest.size = 0,
    };

    if (sig == NULL) {
        DBG("SIGN SIGN estimate\n");
        *siglen = estimate_signature_size(&sctx->pkey->data.pub.publicArea);
        return *siglen > 0;
    }
    else
        DBG("SIGN SIGN\n");

    if (sctx->signature) {
        /* we are about to perform another signature in this context */
        free(sctx->signature);
        sctx->signature = NULL;
    }

    if (tbslen > sizeof(TPMU_HA))
        return 0;
    digest.size = tbslen;
    memcpy(digest.buffer, tbs, tbslen);

    r = Esys_Sign(sctx->esys_ctx, sctx->pkey->object,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  &digest, &sctx->signScheme, &empty_validation, &sctx->signature);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_SIGN, return 0);

    if (!get_signature_buffer(sctx->signature, sig, siglen, sigsize))
        return 0;

    return 1;
}

static int
tpm2_rsa_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey,
                                const OSSL_PARAM params[])
{
    TSS2_RC r;
    TPM2_SIGNATURE_CTX *sctx = ctx;

    DBG("SIGN DIGEST_SIGN_INIT rsa MD=%s\n", mdname);
    sctx->pkey = provkey;

    return (tpm2_rsa_signature_set_ctx_params(sctx, params)
        && rsa_signature_scheme_init(sctx, mdname));
}

static int
tpm2_ecdsa_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey,
                                const OSSL_PARAM params[])
{
    TSS2_RC r;
    TPM2_SIGNATURE_CTX *sctx = ctx;

    DBG("SIGN DIGEST_SIGN_INIT ecdsa MD=%s\n", mdname);
    sctx->pkey = provkey;

    return (tpm2_ecdsa_signature_set_ctx_params(sctx, params)
        && ecdsa_signature_scheme_init(sctx, mdname));
}

static int
digest_sign_start(TPM2_SIGNATURE_CTX *sctx)
{
    TSS2_RC r;
    TPM2B_AUTH null_auth = { .size = 0 };

    if (sctx->signature) {
        DBG("SIGN DIGEST_SIGN_RESTART\n");
        free(sctx->signature);
        sctx->signature = NULL;
    } else
        DBG("SIGN DIGEST_SIGN_START\n");

    r = Esys_HashSequenceStart(sctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &null_auth, sctx->digalg, &sctx->sequenceHandle);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_HASH, return 0);

    return 1;
}

static int
tpm2_signature_digest_sign_update(void *ctx,
                                  const unsigned char *data, size_t datalen)
{
    TSS2_RC r;
    TPM2_SIGNATURE_CTX *sctx = ctx;
    TPM2B_MAX_BUFFER buffer;

    if (sctx->sequenceHandle == ESYS_TR_NONE && !digest_sign_start(sctx))
        return 0;

    DBG("SIGN DIGEST_SIGN_UPDATE\n");
    if (data != NULL) {
        if (datalen > TPM2_MAX_DIGEST_BUFFER)
            return 0;
        buffer.size = datalen;
        memcpy(buffer.buffer, data, datalen);
    }
    else
        buffer.size = 0;

    r = Esys_SequenceUpdate(sctx->esys_ctx, sctx->sequenceHandle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &buffer);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_HASH, return 0);

    return 1;
}

static int
digest_sign_calculate(TPM2_SIGNATURE_CTX *sctx)
{
    TSS2_RC r;
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    DBG("SIGN DIGEST_SIGN_CALCULATE\n");
    r = Esys_SequenceComplete(sctx->esys_ctx, sctx->sequenceHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
#ifdef HAVE_TSS2_ESYS3
                              ESYS_TR_RH_OWNER,
#else
                              TPM2_RH_OWNER,
#endif
                              &digest, &validation);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_HASH, return 0);
    /* the update may be called again to sign another data block */
    sctx->sequenceHandle = ESYS_TR_NONE;

    if (validation->digest.size == 0)
        DBG("SIGN DIGEST_SIGN_CALCULATE zero size ticket\n");

    r = Esys_Sign(sctx->esys_ctx, sctx->pkey->object,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  digest, &sctx->signScheme, validation, &sctx->signature);
    free(digest);
    free(validation);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_SIGN, return 0);

    return 1;
}

static int
tpm2_signature_digest_sign_final(void *ctx,
                                 unsigned char *sig, size_t *siglen, size_t sigsize)
{
    TPM2_SIGNATURE_CTX *sctx = ctx;

    if (!sctx->signature) {
        /* it is possible to digest an empty sequence without calling update */
        if (sctx->sequenceHandle == ESYS_TR_NONE && !digest_sign_start(sctx))
            return 0;

        if (!digest_sign_calculate(sctx))
            return 0;
    }

    DBG("SIGN DIGEST_SIGN_FINAL\n");
    if (!get_signature_buffer(sctx->signature, sig, siglen, sigsize))
        return 0;

    return 1;
}

static int
tpm2_signature_digest_sign(void *ctx, unsigned char *sig, size_t *siglen,
                           size_t sigsize, const unsigned char *data, size_t datalen)
{
    TSS2_RC r;
    TPM2_SIGNATURE_CTX *sctx = ctx;
    TPM2B_MAX_BUFFER buffer;
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    if (sig == NULL) {
        DBG("SIGN DIGEST_SIGN estimate\n");
        *siglen = estimate_signature_size(&sctx->pkey->data.pub.publicArea);
        return *siglen > 0;
    }
    else
        DBG("SIGN DIGEST_SIGN\n");

    if (sctx->signature) {
        /* we are about to perform another signature in this context */
        free(sctx->signature);
        sctx->signature = NULL;
    }

    if (data != NULL) {
        if (datalen > TPM2_MAX_DIGEST_BUFFER)
            return 0;
        buffer.size = datalen;
        memcpy(buffer.buffer, data, datalen);
    }
    else
        buffer.size = 0;

    r = Esys_Hash(sctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                  &buffer, sctx->digalg,
#ifdef HAVE_TSS2_ESYS3
                  ESYS_TR_RH_OWNER,
#else
                  TPM2_RH_OWNER,
#endif
                  &digest, &validation);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_HASH, return 0);

    if (validation->digest.size == 0)
        DBG("SIGN DIGEST_SIGN zero size ticket\n");

    r = Esys_Sign(sctx->esys_ctx, sctx->pkey->object,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  digest, &sctx->signScheme, validation, &sctx->signature);
    free(digest);
    free(validation);
    TPM2_CHECK_RC(sctx->core, r, TPM2_ERR_CANNOT_SIGN, return 0);

    if (!get_signature_buffer(sctx->signature, sig, siglen, sigsize))
        return 0;

    return 1;
}

static int
tpm2_signature_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    TPM2_SIGNATURE_CTX *sctx = ctx;
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("SIGN GET_CTX_PARAMS", params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) {
        unsigned char *aid = NULL;
        int aid_len, r;

        if(!tpm2_sig_scheme_to_x509_alg(&sctx->signScheme,
                &sctx->pkey->data.pub.publicArea.parameters, &aid, &aid_len))
            return 0;

        r = OSSL_PARAM_set_octet_string(p, aid, aid_len);
        free(aid);
        return r;
    }

    return 1;
}

static const OSSL_PARAM *
tpm2_signature_gettable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}

static int
tpm2_rsa_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_SIGNATURE_CTX *sctx = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("SIGN SET_CTX_PARAMS rsa", params);

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int pad_mode;

            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
            sctx->signScheme.scheme = tpm2_num_to_alg_rsa_scheme(pad_mode);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            sctx->signScheme.scheme = tpm2_rsa_scheme_name_to_alg(p->data);
        } else
            return 0;

        if (sctx->signScheme.scheme == TPM2_ALG_ERROR) {
            TPM2_ERROR_raise(sctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
                ((sctx->signScheme.details.any.hashAlg =
                    tpm2_hash_name_to_alg(p->data)) == TPM2_ALG_ERROR)) {
            TPM2_ERROR_raise(sctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL && p->data_type != OSSL_PARAM_UTF8_STRING) {
        /*
         * Per TCG the TPM2 always uses the largest size allowed, so setting
         * a specific salt length is not allowed.
         */
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *
tpm2_rsa_signature_settable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        /* mandatory parameters used by openssl */
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static int
tpm2_ecdsa_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    TPM2_SIGNATURE_CTX *sctx = ctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("SIGN SET_CTX_PARAMS ecdsa", params);

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
                ((sctx->signScheme.details.any.hashAlg =
                    tpm2_hash_name_to_alg(p->data)) == TPM2_ALG_ERROR)) {
            TPM2_ERROR_raise(sctx->core, TPM2_ERR_UNKNOWN_ALGORITHM);
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *
tpm2_ecdsa_signature_settable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

const OSSL_DISPATCH tpm2_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tpm2_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tpm2_signature_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))tpm2_rsa_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))tpm2_signature_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))tpm2_rsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))tpm2_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))tpm2_signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))tpm2_signature_digest_sign },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void(*)(void))tpm2_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void(*)(void))tpm2_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void(*)(void))tpm2_rsa_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_rsa_signature_settable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH tpm2_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tpm2_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tpm2_signature_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))tpm2_ecdsa_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))tpm2_signature_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))tpm2_ecdsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))tpm2_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))tpm2_signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))tpm2_signature_digest_sign },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void(*)(void))tpm2_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void(*)(void))tpm2_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void(*)(void))tpm2_ecdsa_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_ecdsa_signature_settable_ctx_params },
    { 0, NULL }
};

