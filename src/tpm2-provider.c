/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include <tss2/tss2_tctildr.h>

#include "tpm2-provider.h"

#define TPM2TSS_PROV_NAME "TPM 2.0 Provider"
#define TPM2TSS_PROV_VERSION PACKAGE_VERSION
#define TPM2TSS_PROV_BUILDINFO PACKAGE_VERSION

static const OSSL_PARAM *
tpm2_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
    };

    return param_types;
}

static int
tpm2_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TPM2TSS_PROV_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TPM2TSS_PROV_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TPM2TSS_PROV_BUILDINFO))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* always in running state */
        return 0;

    return 1;
}

#define TPM2_PROPS(op) ("provider=tpm2,tpm2." #op)

typedef struct {
    const char *algs;
    const char *props;
    tpm2_dispatch_t *dispatch;
} TPM2_ALGORITHM;

static const OSSL_ALGORITHM *
tpm2_operation(const TPM2_CAPABILITY *caps,
               const TPM2_ALGORITHM *algs, size_t algs_size)
{
    OSSL_ALGORITHM *res;
    int i, j = 0;

    if ((res = OPENSSL_malloc(algs_size * sizeof(OSSL_ALGORITHM))) == NULL)
        return NULL;

    for (i = 0; algs[i].algs != NULL; i++) {
        /* retrieve the implementation,
         * or NULL when the current TPM does not support this algorithm */
        if ((res[j].implementation = algs[i].dispatch(caps)) == NULL)
            continue;
        res[j].algorithm_names = algs[i].algs;
        res[j].property_definition = algs[i].props;
        res[j].algorithm_description = NULL;
        j++;
    }

    /* termination */
    res[j].algorithm_names = NULL;
    return res;
}

#if WITH_OP_DIGEST
extern tpm2_dispatch_t tpm2_digest_SHA1_dispatch;
extern tpm2_dispatch_t tpm2_digest_SHA256_dispatch;
extern tpm2_dispatch_t tpm2_digest_SHA384_dispatch;
extern tpm2_dispatch_t tpm2_digest_SHA512_dispatch;
extern tpm2_dispatch_t tpm2_digest_SM3_256_dispatch;

static const TPM2_ALGORITHM tpm2_digests[] = {
    { "SHA1:SHA-1:SSL3-SHA1", TPM2_PROPS(digest), &tpm2_digest_SHA1_dispatch },
    { "SHA2-256:SHA-256:SHA256", TPM2_PROPS(digest), &tpm2_digest_SHA256_dispatch },
    { "SHA2-384:SHA-384:SHA384", TPM2_PROPS(digest), &tpm2_digest_SHA384_dispatch },
    { "SHA2-512:SHA-512:SHA512", TPM2_PROPS(digest), &tpm2_digest_SHA512_dispatch },
    { "SM3", TPM2_PROPS(digest), &tpm2_digest_SM3_256_dispatch },
    { NULL, NULL, NULL }
};
#endif /* WITH_OP_DIGEST */

#if WITH_OP_CIPHER
#define DECLARE_3CIPHERS_DISPATCH(alg,lcmode) \
    extern tpm2_dispatch_t tpm2_cipher_##alg##128##lcmode##_dispatch; \
    extern tpm2_dispatch_t tpm2_cipher_##alg##192##lcmode##_dispatch; \
    extern tpm2_dispatch_t tpm2_cipher_##alg##256##lcmode##_dispatch;

#define DECLARE_3CIPHERS_ALGORITHMS(alg,lcmode) \
    { #alg "-128-" #lcmode, TPM2_PROPS(cipher), &tpm2_cipher_##alg##128##lcmode##_dispatch }, \
    { #alg "-192-" #lcmode, TPM2_PROPS(cipher), &tpm2_cipher_##alg##192##lcmode##_dispatch }, \
    { #alg "-256-" #lcmode, TPM2_PROPS(cipher), &tpm2_cipher_##alg##256##lcmode##_dispatch },

DECLARE_3CIPHERS_DISPATCH(AES,ECB)
DECLARE_3CIPHERS_DISPATCH(AES,CBC)
DECLARE_3CIPHERS_DISPATCH(AES,OFB)
DECLARE_3CIPHERS_DISPATCH(AES,CFB)
DECLARE_3CIPHERS_DISPATCH(AES,CTR)
DECLARE_3CIPHERS_DISPATCH(CAMELLIA,ECB)
DECLARE_3CIPHERS_DISPATCH(CAMELLIA,CBC)
DECLARE_3CIPHERS_DISPATCH(CAMELLIA,OFB)
DECLARE_3CIPHERS_DISPATCH(CAMELLIA,CFB)
DECLARE_3CIPHERS_DISPATCH(CAMELLIA,CTR)

static const TPM2_ALGORITHM tpm2_ciphers[] = {
    DECLARE_3CIPHERS_ALGORITHMS(AES,ECB)
    { "AES-128-CBC:AES128", TPM2_PROPS(cipher), &tpm2_cipher_AES128CBC_dispatch },
    { "AES-192-CBC:AES192", TPM2_PROPS(cipher), &tpm2_cipher_AES192CBC_dispatch },
    { "AES-256-CBC:AES256", TPM2_PROPS(cipher), &tpm2_cipher_AES256CBC_dispatch },
    DECLARE_3CIPHERS_ALGORITHMS(AES,OFB)
    DECLARE_3CIPHERS_ALGORITHMS(AES,CFB)
    DECLARE_3CIPHERS_ALGORITHMS(AES,CTR)
    DECLARE_3CIPHERS_ALGORITHMS(CAMELLIA,ECB)
    { "CAMELLIA-128-CBC:CAMELLIA128", TPM2_PROPS(cipher), &tpm2_cipher_CAMELLIA128CBC_dispatch },
    { "CAMELLIA-192-CBC:CAMELLIA192", TPM2_PROPS(cipher), &tpm2_cipher_CAMELLIA192CBC_dispatch },
    { "CAMELLIA-256-CBC:CAMELLIA256", TPM2_PROPS(cipher), &tpm2_cipher_CAMELLIA256CBC_dispatch },
    DECLARE_3CIPHERS_ALGORITHMS(CAMELLIA,OFB)
    DECLARE_3CIPHERS_ALGORITHMS(CAMELLIA,CFB)
    DECLARE_3CIPHERS_ALGORITHMS(CAMELLIA,CTR)
    { NULL, NULL, NULL }
};
#endif /* WITH_OP_CIPHER */

extern const OSSL_DISPATCH tpm2_rand_functions[];

static const OSSL_ALGORITHM tpm2_rands[] = {
    /* TODO: Does this need to be variying?
       For example, ST32TPHF is using a FIPS compliant SHA256 DRBG */
    { "CTR-DRBG" /*"HASH-DRBG"*/, TPM2_PROPS(rand), tpm2_rand_functions },
    { NULL, NULL, NULL }
};

#define PROV_NAMES_EC "EC:id-ecPublicKey:1.2.840.10045.2.1"
#define PROV_NAMES_ECDH "ECDH"
#define PROV_NAMES_ECDSA "ECDSA"
#define PROV_NAMES_RSA "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define PROV_NAMES_RSA_PSS "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10"

extern tpm2_dispatch_t tpm2_rsa_keymgmt_dispatch;
extern tpm2_dispatch_t tpm2_rsapss_keymgmt_dispatch;
extern tpm2_dispatch_t tpm2_ec_keymgmt_dispatch;

static const TPM2_ALGORITHM tpm2_keymgmts[] = {
    { PROV_NAMES_RSA, "provider=tpm2", &tpm2_rsa_keymgmt_dispatch },
    { PROV_NAMES_RSA_PSS, "provider=tpm2", &tpm2_rsapss_keymgmt_dispatch },
    { PROV_NAMES_EC, "provider=tpm2", &tpm2_ec_keymgmt_dispatch },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_ecdh_keyexch_functions[];

static const OSSL_ALGORITHM tpm2_keyexchs[] = {
    { PROV_NAMES_ECDH, "provider=tpm2", tpm2_ecdh_keyexch_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_signature_functions[];
extern const OSSL_DISPATCH tpm2_ecdsa_signature_functions[];

static const OSSL_ALGORITHM tpm2_signatures[] = {
    { PROV_NAMES_RSA, TPM2_PROPS(signature), tpm2_rsa_signature_functions },
    { PROV_NAMES_ECDSA, TPM2_PROPS(signature), tpm2_ecdsa_signature_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_asymcipher_functions[];

static const OSSL_ALGORITHM tpm2_asymciphers[] = {
    { PROV_NAMES_RSA, "provider=tpm2", tpm2_rsa_asymcipher_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_tss_encoder_PrivateKeyInfo_der_functions[];
extern const OSSL_DISPATCH tpm2_tss_encoder_PrivateKeyInfo_pem_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_SubjectPublicKeyInfo_der_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_SubjectPublicKeyInfo_pem_functions[];
extern const OSSL_DISPATCH tpm2_rsapss_encoder_SubjectPublicKeyInfo_der_functions[];
extern const OSSL_DISPATCH tpm2_rsapss_encoder_SubjectPublicKeyInfo_pem_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_text_functions[];
extern const OSSL_DISPATCH tpm2_ec_encoder_SubjectPublicKeyInfo_der_functions[];
extern const OSSL_DISPATCH tpm2_ec_encoder_SubjectPublicKeyInfo_pem_functions[];
extern const OSSL_DISPATCH tpm2_ec_encoder_text_functions[];

static const OSSL_ALGORITHM tpm2_encoders[] = {
    /* private key */
    { "RSA", "provider=tpm2,output=der,structure=PrivateKeyInfo", tpm2_tss_encoder_PrivateKeyInfo_der_functions },
    { "RSA", "provider=tpm2,output=pem,structure=PrivateKeyInfo", tpm2_tss_encoder_PrivateKeyInfo_pem_functions },
    { "RSA-PSS", "provider=tpm2,output=der,structure=PrivateKeyInfo", tpm2_tss_encoder_PrivateKeyInfo_der_functions },
    { "RSA-PSS", "provider=tpm2,output=pem,structure=PrivateKeyInfo", tpm2_tss_encoder_PrivateKeyInfo_pem_functions },
    { "EC", "provider=tpm2,output=der,structure=PrivateKeyInfo", tpm2_tss_encoder_PrivateKeyInfo_der_functions },
    { "EC", "provider=tpm2,output=pem,structure=PrivateKeyInfo", tpm2_tss_encoder_PrivateKeyInfo_pem_functions },
    /* public key */
    { "RSA", "provider=tpm2,output=der,structure=pkcs1", tpm2_rsa_encoder_pkcs1_der_functions },
    { "RSA", "provider=tpm2,output=pem,structure=pkcs1", tpm2_rsa_encoder_pkcs1_pem_functions },
    { "RSA", "provider=tpm2,output=der,structure=SubjectPublicKeyInfo", tpm2_rsa_encoder_SubjectPublicKeyInfo_der_functions },
    { "RSA", "provider=tpm2,output=pem,structure=SubjectPublicKeyInfo", tpm2_rsa_encoder_SubjectPublicKeyInfo_pem_functions },
    { "RSA", "provider=tpm2,output=text", tpm2_rsa_encoder_text_functions },
    { "RSA-PSS", "provider=tpm2,output=der,structure=pkcs1", tpm2_rsa_encoder_pkcs1_der_functions },
    { "RSA-PSS", "provider=tpm2,output=pem,structure=pkcs1", tpm2_rsa_encoder_pkcs1_pem_functions },
    { "RSA-PSS", "provider=tpm2,output=der,structure=SubjectPublicKeyInfo", tpm2_rsapss_encoder_SubjectPublicKeyInfo_der_functions },
    { "RSA-PSS", "provider=tpm2,output=pem,structure=SubjectPublicKeyInfo", tpm2_rsapss_encoder_SubjectPublicKeyInfo_pem_functions },
    { "RSA-PSS", "provider=tpm2,output=text", tpm2_rsa_encoder_text_functions },
    { "EC", "provider=tpm2,output=der,structure=SubjectPublicKeyInfo", tpm2_ec_encoder_SubjectPublicKeyInfo_der_functions },
    { "EC", "provider=tpm2,output=pem,structure=SubjectPublicKeyInfo", tpm2_ec_encoder_SubjectPublicKeyInfo_pem_functions },
    { "EC", "provider=tpm2,output=text", tpm2_ec_encoder_text_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_der_decoder_functions[];
extern const OSSL_DISPATCH tpm2_tss_to_rsa_decoder_functions[];
extern const OSSL_DISPATCH tpm2_tss_to_ec_decoder_functions[];

static const OSSL_ALGORITHM tpm2_decoders[] = {
    { "DER", "provider=tpm2,input=pem", tpm2_der_decoder_functions },
    { "RSA", "provider=tpm2,input=der,structure=TSS2", tpm2_tss_to_rsa_decoder_functions },
    { "EC", "provider=tpm2,input=der,structure=TSS2", tpm2_tss_to_ec_decoder_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_handle_store_functions[];

static const OSSL_ALGORITHM tpm2_stores[] = {
    { "handle", TPM2_PROPS(store), tpm2_handle_store_functions },
    { "object", TPM2_PROPS(store), tpm2_handle_store_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *
tpm2_query_operation(void *provctx, int operation_id, int *no_cache)
{
    TPM2_PROVIDER_CTX *cprov = provctx;

    *no_cache = 0;

    switch (operation_id) {
#if WITH_OP_DIGEST
    case OSSL_OP_DIGEST:
        /* we have to return the list of currently supported algorithms, because
         * the TLS uses this information for algorithm negotiation */
        return tpm2_operation(&cprov->capability, tpm2_digests, NELEMS(tpm2_digests));
#endif
#if WITH_OP_CIPHER
    case OSSL_OP_CIPHER:
        return tpm2_operation(&cprov->capability, tpm2_ciphers, NELEMS(tpm2_ciphers));
#endif
    case OSSL_OP_RAND:
        return tpm2_rands;
    case OSSL_OP_KEYMGMT:
        return tpm2_operation(&cprov->capability, tpm2_keymgmts, NELEMS(tpm2_keymgmts));
    case OSSL_OP_KEYEXCH:
        return tpm2_keyexchs;
    case OSSL_OP_SIGNATURE:
        return tpm2_signatures;
    case OSSL_OP_ASYM_CIPHER:
        return tpm2_asymciphers;
    case OSSL_OP_ENCODER:
        return tpm2_encoders;
    case OSSL_OP_DECODER:
        return tpm2_decoders;
    case OSSL_OP_STORE:
        return tpm2_stores;
    }
    return NULL;
}

static void
tpm2_unquery_operation(void *provctx, int operation_id, const OSSL_ALGORITHM *alg)
{
    switch (operation_id) {
#if WITH_OP_DIGEST
    case OSSL_OP_DIGEST:
#endif
#if WITH_OP_CIPHER
    case OSSL_OP_CIPHER:
#endif
    case OSSL_OP_KEYMGMT:
        OPENSSL_free((void *)alg);
        break;
    }
}

static const OSSL_ITEM *
tpm2_get_reason_strings(void *provctx)
{
    static const OSSL_ITEM reason_strings[] = {
        {TPM2_ERR_MEMORY_FAILURE, "memory allocation failure"},
        {TPM2_ERR_AUTHORIZATION_FAILURE, "authorization failure"},
        {TPM2_ERR_UNKNOWN_ALGORITHM, "unknown algorithm"},
        {TPM2_ERR_INPUT_CORRUPTED, "input corrupted"},
        {TPM2_ERR_WRONG_DATA_LENGTH, "wrong data length"},
        {TPM2_ERR_CANNOT_CONNECT, "cannot connect"},
        {TPM2_ERR_CANNOT_GET_CAPABILITY, "cannot get capability"},
        {TPM2_ERR_CANNOT_GET_RANDOM, "cannot get random"},
        {TPM2_ERR_CANNOT_LOAD_PARENT, "cannot load parent"},
        {TPM2_ERR_CANNOT_CREATE_PRIMARY, "cannot create primary"},
        {TPM2_ERR_CANNOT_CREATE_KEY, "cannot create key"},
        {TPM2_ERR_CANNOT_LOAD_KEY, "cannot load key"},
        {TPM2_ERR_CANNOT_GENERATE, "cannot generate"},
        {TPM2_ERR_CANNOT_HASH, "cannot hash"},
        {TPM2_ERR_CANNOT_SIGN, "cannot sign"},
        {TPM2_ERR_VERIFICATION_FAILED, "verification failed"},
        {TPM2_ERR_CANNOT_ENCRYPT, "cannot encrypt"},
        {TPM2_ERR_CANNOT_DECRYPT, "cannot decrypt"},
        {TPM2_ERR_CANNOT_DUPLICATE, "cannot duplicate context"},
        {0, NULL}
    };

    return reason_strings;
}

extern int tpm2_tls_group_capability(TPM2_PROVIDER_CTX *provctx, OSSL_CALLBACK *cb, void *arg);

static int tpm2_get_capabilities(void *provctx, const char *capability,
                                 OSSL_CALLBACK *cb, void *arg)
{
    TPM2_PROVIDER_CTX *cprov = provctx;

    DBG("PROVIDER GET_CAPABILITIES %s\n", capability);
    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0)
        return tpm2_tls_group_capability(cprov, cb, arg);

    return 0;
}

static int
tpm2_self_test(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TSS2_RC r;

    DBG("PROVIDER SELFTEST\n");
    r = Esys_SelfTest(cprov->esys_ctx,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                      TPM2_YES);

    return r == TPM2_RC_SUCCESS;
}

static void
tpm2_teardown(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC r;

    DBG("PROVIDER TEARDOWN\n");
    free(cprov->capability.properties);
    free(cprov->capability.algorithms);
    free(cprov->capability.commands);
    free(cprov->capability.curves);
    OSSL_LIB_CTX_free(cprov->libctx);

    r = Esys_GetTcti(cprov->esys_ctx, &tcti_ctx);
    Esys_Finalize(&cprov->esys_ctx);
    if (r == TSS2_RC_SUCCESS) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }

    OPENSSL_clear_free(cprov, sizeof(TPM2_PROVIDER_CTX));
}

static const OSSL_DISPATCH tpm2_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tpm2_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tpm2_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tpm2_query_operation },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))tpm2_unquery_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))tpm2_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))tpm2_get_capabilities },
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))tpm2_self_test },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tpm2_teardown },
    { 0, NULL }
};

/* openssl configuration settings */
#define TPM2_PROV_PARAM_TCTI "tcti"

OPENSSL_EXPORT int
OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                   const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                   void **provctx)
{
    TPM2_PROVIDER_CTX *cprov;
    char *tcti_nameconf = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC r;

    DBG("PROVIDER INIT\n");
    if ((cprov = OPENSSL_zalloc(sizeof(TPM2_PROVIDER_CTX))) == NULL)
        return 0;

    cprov->core = handle;
    init_core_func_from_dispatch(in);
    if ((cprov->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in)) == NULL)
        goto err1;

    tcti_nameconf = getenv("TPM2OPENSSL_TCTI");
    if (tcti_nameconf == NULL) {
        OSSL_PARAM core_params[] = {
            OSSL_PARAM_utf8_ptr(TPM2_PROV_PARAM_TCTI, tcti_nameconf, 0),
            OSSL_PARAM_END
        };

        if (!tpm2_core_get_params(handle, core_params))
            goto err1;
    }

    r = Tss2_TctiLdr_Initialize(tcti_nameconf, &tcti_ctx);
    TPM2_CHECK_RC(cprov->core, r, TPM2_ERR_CANNOT_CONNECT, goto err1);

    r = Esys_Initialize(&cprov->esys_ctx, tcti_ctx, NULL);
    TPM2_CHECK_RC(cprov->core, r, TPM2_ERR_CANNOT_CONNECT, goto err2);

#define LOAD_CAPABILITY(capname, capcount, capbuf) \
    r = Esys_GetCapability(cprov->esys_ctx, \
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, \
                           capname, 0, capcount, NULL, capbuf); \
    TPM2_CHECK_RC(cprov->core, r, TPM2_ERR_CANNOT_GET_CAPABILITY, goto err3);

    LOAD_CAPABILITY(TPM2_CAP_TPM_PROPERTIES, TPM2_MAX_TPM_PROPERTIES, &cprov->capability.properties)
    LOAD_CAPABILITY(TPM2_CAP_ALGS, TPM2_MAX_CAP_ALGS, &cprov->capability.algorithms)
    LOAD_CAPABILITY(TPM2_CAP_COMMANDS, TPM2_MAX_CAP_CC, &cprov->capability.commands)
    LOAD_CAPABILITY(TPM2_CAP_ECC_CURVES, TPM2_MAX_ECC_CURVES, &cprov->capability.curves)

    *out = tpm2_dispatch_table;
    *provctx = cprov;

    return 1;
err3:
    Esys_Finalize(&cprov->esys_ctx);
err2:
    Tss2_TctiLdr_Finalize(&tcti_ctx);
err1:
    OSSL_LIB_CTX_free(cprov->libctx);
    OPENSSL_clear_free(cprov, sizeof(TPM2_PROVIDER_CTX));
    return 0;
}

