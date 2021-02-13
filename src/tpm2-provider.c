/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include <tss2/tss2_tctildr.h>

#include "tpm2-provider.h"

#define TPM2TSS_PROV_NAME "TPM 2.0 Provider"
#define TPM2TSS_PROV_VERSION "2.0.0"
#define TPM2TSS_PROV_BUILDINFO "BETA"

static const OSSL_PARAM *
tpm2_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
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

    return 1;
}

extern const OSSL_DISPATCH tpm2_digest_SHA1_functions[];
extern const OSSL_DISPATCH tpm2_digest_SHA256_functions[];
extern const OSSL_DISPATCH tpm2_digest_SHA384_functions[];
extern const OSSL_DISPATCH tpm2_digest_SHA512_functions[];
extern const OSSL_DISPATCH tpm2_digest_SM3_256_functions[];

static const OSSL_ALGORITHM tpm2_digests[] = {
    { "SHA1:SHA-1:SSL3-SHA1", "provider=tpm2", tpm2_digest_SHA1_functions },
    { "SHA2-256:SHA-256:SHA256", "provider=tpm2", tpm2_digest_SHA256_functions },
    { "SHA2-384:SHA-384:SHA384", "provider=tpm2", tpm2_digest_SHA384_functions },
    { "SHA2-512:SHA-512:SHA512", "provider=tpm2", tpm2_digest_SHA512_functions },
    { "SM3", "provider=tpm2", tpm2_digest_SM3_256_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_cipher_AES128CBC_functions[];
extern const OSSL_DISPATCH tpm2_cipher_AES192CBC_functions[];
extern const OSSL_DISPATCH tpm2_cipher_AES256CBC_functions[];

static const OSSL_ALGORITHM tpm2_ciphers[] = {
    { "AES-128-CBC:AES128", "provider=tpm2", tpm2_cipher_AES128CBC_functions },
    { "AES-192-CBC:AES192", "provider=tpm2", tpm2_cipher_AES192CBC_functions },
    { "AES-256-CBC:AES256", "provider=tpm2", tpm2_cipher_AES256CBC_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rand_functions[];

static const OSSL_ALGORITHM tpm2_rands[] = {
    /* TODO: Does this need to be variying?
       For example, ST32TPHF is using a FIPS compliant SHA256 DRBG */
    { "CTR-DRBG" /*"HASH-DRBG"*/, "provider=tpm2", tpm2_rand_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_keymgmt_functions[];

static const OSSL_ALGORITHM tpm2_keymgmts[] = {
    { "RSA:rsaEncryption", "provider=tpm2", tpm2_rsa_keymgmt_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_signature_functions[];

static const OSSL_ALGORITHM tpm2_signatures[] = {
    { "RSA:rsaEncryption", "provider=tpm2", tpm2_rsa_signature_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_asymcipher_functions[];

static const OSSL_ALGORITHM tpm2_asymciphers[] = {
    { "RSA:rsaEncryption", "provider=tpm2", tpm2_rsa_asymcipher_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_encoder_pkcs8_pem_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_SubjectPublicKeyInfo_der_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_SubjectPublicKeyInfo_pem_functions[];
extern const OSSL_DISPATCH tpm2_rsa_encoder_text_functions[];

static const OSSL_ALGORITHM tpm2_encoders[] = {
    /* private key */
    { "RSA", "provider=tpm2,output=pem,structure=pkcs8", tpm2_rsa_encoder_pkcs8_pem_functions },
    /* public key */
    { "RSA", "provider=tpm2,output=der,structure=pkcs1", tpm2_rsa_encoder_pkcs1_der_functions },
    { "RSA", "provider=tpm2,output=pem,structure=pkcs1", tpm2_rsa_encoder_pkcs1_pem_functions },
    { "RSA", "provider=tpm2,output=der,structure=SubjectPublicKeyInfo", tpm2_rsa_encoder_SubjectPublicKeyInfo_der_functions },
    { "RSA", "provider=tpm2,output=pem,structure=SubjectPublicKeyInfo", tpm2_rsa_encoder_SubjectPublicKeyInfo_pem_functions },
    { "RSA", "provider=tpm2,output=text", tpm2_rsa_encoder_text_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_rsa_decoder_PEM_functions[];
extern const OSSL_DISPATCH tpm2_rsa_decoder_DER_functions[];

static const OSSL_ALGORITHM tpm2_decoders[] = {
    { "RSA:rsaEncryption", "provider=tpm2,input=pem", tpm2_rsa_decoder_PEM_functions },
    { "RSA:rsaEncryption", "provider=tpm2,input=der", tpm2_rsa_decoder_DER_functions },
    { NULL, NULL, NULL }
};

extern const OSSL_DISPATCH tpm2_file_store_functions[];
extern const OSSL_DISPATCH tpm2_handle_store_functions[];

static const OSSL_ALGORITHM tpm2_stores[] = {
    { "file", "provider=tpm2", tpm2_file_store_functions },
    { "handle", "provider=tpm2", tpm2_handle_store_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *
tpm2_query_operation(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return tpm2_digests;
    case OSSL_OP_CIPHER:
        return tpm2_ciphers;
    case OSSL_OP_RAND:
        return tpm2_rands;
    case OSSL_OP_KEYMGMT:
        return tpm2_keymgmts;
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
        {TPM2_ERR_CANNOT_HASH, "cannot hash"},
        {TPM2_ERR_CANNOT_SIGN, "cannot sign"},
        {TPM2_ERR_CANNOT_ENCRYPT, "cannot encrypt"},
        {TPM2_ERR_CANNOT_DECRYPT, "cannot decrypt"},
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
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_RC r;

    DBG("PROVIDER TEARDOWN\n");
    BIO_meth_free(cprov->corebiometh);

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
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))tpm2_get_reason_strings },
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
    TPM2_PROVIDER_CTX *cprov = OPENSSL_zalloc(sizeof(TPM2_PROVIDER_CTX));
    char *tcti_nameconf = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC r;

    DBG("PROVIDER INIT\n");
    if (cprov == NULL)
        return 0;

    cprov->core = handle;
    init_core_func_from_dispatch(in);
    cprov->corebiometh = bio_prov_init_bio_method();

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

    *out = tpm2_dispatch_table;
    *provctx = cprov;

    return 1;
err2:
    Tss2_TctiLdr_Finalize(&tcti_ctx);
err1:
    OPENSSL_clear_free(cprov, sizeof(TPM2_PROVIDER_CTX));
    return 0;
}

