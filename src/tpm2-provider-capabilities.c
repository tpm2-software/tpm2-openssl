/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#include "tpm2-provider.h"

/* TLS-GROUP */

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

static struct {
    TPM2_ECC_CURVE curve;
    OSSL_PARAM params[10];
} param_tls_group_list[] = {
    { TPM2_ECC_NIST_P192, TLS_GROUP_ENTRY("secp192r1", "prime192v1", "EC", 0) },
    { TPM2_ECC_NIST_P192, TLS_GROUP_ENTRY("P-192", "prime192v1", "EC", 0) },
    { TPM2_ECC_NIST_P224, TLS_GROUP_ENTRY("secp224r1", "secp224r1", "EC", 1) },
    { TPM2_ECC_NIST_P224, TLS_GROUP_ENTRY("P-224", "secp224r1", "EC", 1) },
    { TPM2_ECC_NIST_P256, TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 2) },
    { TPM2_ECC_NIST_P256, TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 2) },
    { TPM2_ECC_NIST_P384, TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 3) },
    { TPM2_ECC_NIST_P384, TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 3) },
    { TPM2_ECC_NIST_P521, TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 4) },
    { TPM2_ECC_NIST_P521, TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 4) },
};

int
tpm2_tls_group_capability(TPM2_PROVIDER_CTX *provctx, OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < NELEMS(param_tls_group_list); i++) {
        if (tpm2_supports_curve(provctx->capability.curves, param_tls_group_list[i].curve)
                && !cb(param_tls_group_list[i].params, arg))
            return 0;
    }

    return 1;
}
