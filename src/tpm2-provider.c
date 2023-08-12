/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/prov_ssl.h>

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
               const TPM2_ALGORITHM *algs, size_t count)
{
    OSSL_ALGORITHM *res;
    int i, j = 0;

    if ((res = OPENSSL_malloc(count * sizeof(OSSL_ALGORITHM))) == NULL)
        return NULL;

    for (i = 0; i < count && algs[i].algs != NULL; i++) {
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

extern tpm2_dispatch_t tpm2_rsa_keymgmt_dispatch;
extern tpm2_dispatch_t tpm2_rsapss_keymgmt_dispatch;
extern tpm2_dispatch_t tpm2_ec_keymgmt_dispatch;

static const TPM2_ALGORITHM tpm2_keymgmts[] = {
    { "RSA:rsaEncryption", "provider=tpm2", &tpm2_rsa_keymgmt_dispatch },
    { "RSA-PSS:RSASSA-PSS", "provider=tpm2", &tpm2_rsapss_keymgmt_dispatch },
    { "EC:id-ecPublicKey", "provider=tpm2", &tpm2_ec_keymgmt_dispatch },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_ecdh_keyexch_functions[];

static const OSSL_ALGORITHM tpm2_keyexchs[] = {
    { "ECDH", "provider=tpm2", tpm2_ecdh_keyexch_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_signature_functions[];
extern const OSSL_DISPATCH tpm2_ecdsa_signature_functions[];

static const OSSL_ALGORITHM tpm2_signatures[] = {
    { "RSA:rsaEncryption", TPM2_PROPS(signature), tpm2_rsa_signature_functions },
    { "ECDSA", TPM2_PROPS(signature), tpm2_ecdsa_signature_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_asymcipher_functions[];

static const OSSL_ALGORITHM tpm2_asymciphers[] = {
    { "RSA:rsaEncryption", "provider=tpm2", tpm2_rsa_asymcipher_functions },
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
    { "RSA:rsaEncryption", "provider=tpm2,input=der,structure=TSS2", tpm2_tss_to_rsa_decoder_functions },
    { "EC:id-ecPublicKey", "provider=tpm2,input=der,structure=TSS2", tpm2_tss_to_ec_decoder_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_object_store_functions[];

static const OSSL_ALGORITHM tpm2_stores[] = {
    { "object", TPM2_PROPS(store), tpm2_object_store_functions },
    { "handle", TPM2_PROPS(store), tpm2_object_store_functions },
    { NULL, NULL, NULL }
};

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

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
    OSSL_LIB_CTX_free(cprov->libctx);

    r = Esys_GetTcti(cprov->esys_ctx, &tcti_ctx);
    Esys_Finalize(&cprov->esys_ctx);
    if (r == TSS2_RC_SUCCESS) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }

    OPENSSL_clear_free(cprov, sizeof(TPM2_PROVIDER_CTX));
}

typedef struct tls_group_constants_st {
    unsigned int group_id;   /* Group ID */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

#define TLS_GROUP_ID_secp192r1 19
#define TLS_GROUP_ID_secp224r1 21
#define TLS_GROUP_ID_secp256r1 23
#define TLS_GROUP_ID_secp384r1 24
#define TLS_GROUP_ID_secp521r1 25

static const TLS_GROUP_CONSTANTS tls_group_list[] = {
    { TLS_GROUP_ID_secp192r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { TLS_GROUP_ID_secp224r1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
};

#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               tlsname, \
                               sizeof(tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               realname, \
                               sizeof(realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               algorithm, \
                               sizeof(algorithm)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&tls_group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&tls_group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                       (int *)&tls_group_list[idx].mintls),     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                       (int *)&tls_group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                       (int *)&tls_group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                       (int *)&tls_group_list[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_tls_group_list[][10] = {
    TLS_GROUP_ENTRY("secp192r1", "prime192v1", "EC", 0),
    TLS_GROUP_ENTRY("P-192", "prime192v1", "EC", 0), /* Alias of previous */
    TLS_GROUP_ENTRY("secp224r1", "secp224r1", "EC", 1),
    TLS_GROUP_ENTRY("P-224", "secp224r1", "EC", 1), /* Alias of previous */
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 2),
    TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 2), /* Alias of previous */
    TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 3),
    TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 3), /* Alias of previous */
    TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 4),
    TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 4), /* Alias of above */
};

static int tpm2_get_capabilities(void *provctx, const char *capability,
                                 OSSL_CALLBACK *cb, void *arg)
{
    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0) {
        size_t i;

        for (i = 0; i < NELEMS(param_tls_group_list); i++)
            if (!cb(param_tls_group_list[i], arg))
                return 0;

        return 1;
    }

    return 0;
}

static const OSSL_DISPATCH tpm2_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tpm2_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tpm2_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tpm2_query_operation },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))tpm2_unquery_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))tpm2_get_reason_strings },
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))tpm2_self_test },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tpm2_teardown },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))tpm2_get_capabilities },
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

    r = Esys_GetCapability(cprov->esys_ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_TPM_PROPERTIES, 0, TPM2_MAX_TPM_PROPERTIES,
                           NULL, &cprov->capability.properties);
    TPM2_CHECK_RC(cprov->core, r, TPM2_ERR_CANNOT_GET_CAPABILITY, goto err3);

    r = Esys_GetCapability(cprov->esys_ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_ALGS, 0, TPM2_MAX_CAP_ALGS,
                           NULL, &cprov->capability.algorithms);
    TPM2_CHECK_RC(cprov->core, r, TPM2_ERR_CANNOT_GET_CAPABILITY, goto err3);

    r = Esys_GetCapability(cprov->esys_ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_COMMANDS, 0, TPM2_MAX_CAP_CC,
                           NULL, &cprov->capability.commands);
    TPM2_CHECK_RC(cprov->core, r, TPM2_ERR_CANNOT_GET_CAPABILITY, goto err3);

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

