/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>

#include "tpm2-provider-algorithms.h"

typedef struct {
    const char *name;
    TPMI_ALG_HASH alg;
} hash_names_t;

static const hash_names_t hashes[] = {
    { "SHA1", TPM2_ALG_SHA1 },
    { "SHA-1", TPM2_ALG_SHA1 },
    { "SHA256", TPM2_ALG_SHA256 },
    { "SHA-256", TPM2_ALG_SHA256 },
    { "SHA2-256", TPM2_ALG_SHA256 },
    { "SHA384", TPM2_ALG_SHA384 },
    { "SHA-384", TPM2_ALG_SHA384 },
    { "SHA2-384", TPM2_ALG_SHA384 },
    { "SHA512", TPM2_ALG_SHA512 },
    { "SHA-512", TPM2_ALG_SHA512 },
    { "SHA2-512", TPM2_ALG_SHA512 },
    { NULL, TPM2_ALG_ERROR }
};

TPMI_ALG_HASH
tpm2_hash_name_to_alg(const char *name)
{
    const hash_names_t *nameptr;

    for (nameptr = hashes; nameptr->name != NULL; nameptr++) {
        if (!strcasecmp(name, nameptr->name))
            return nameptr->alg;
    }

    return TPM2_ALG_ERROR;
}

const char *
tpm2_hash_alg_to_name(const TPMI_ALG_HASH alg)
{
    const hash_names_t *nameptr;

    for (nameptr = hashes; nameptr->name != NULL; nameptr++) {
        if (alg == nameptr->alg)
            return nameptr->name;
    }

    return NULL;
}

typedef struct {
    const char *name;
    TPMI_ALG_RSA_SCHEME alg;
} scheme_names_t;

static const scheme_names_t schemes[] = {
    { "PKCS1", TPM2_ALG_RSASSA },
    { "PSS", TPM2_ALG_RSAPSS },
    { NULL, TPM2_ALG_ERROR }
};

TPMI_ALG_RSA_SCHEME
tpm2_num_to_alg_rsa_scheme(const int num)
{
    switch (num)
    {
    case RSA_PKCS1_PSS_PADDING:
        return TPM2_ALG_RSAPSS;
    default:
        return TPM2_ALG_ERROR;
    }
}

TPMI_ALG_RSA_SCHEME
tpm2_rsa_scheme_name_to_alg(const char *name)
{
    const scheme_names_t *nameptr;

    for (nameptr = schemes; nameptr->name != NULL; nameptr++) {
        if (!strcasecmp(name, nameptr->name))
            return nameptr->alg;
    }

    return TPM2_ALG_ERROR;
}

const char *
tpm2_rsa_scheme_alg_to_name(const TPMI_ALG_RSA_SCHEME alg)
{
    const scheme_names_t *nameptr;

    for (nameptr = schemes; nameptr->name != NULL; nameptr++) {
        if (alg == nameptr->alg)
            return nameptr->name;
    }

    return NULL;
}

X509_ALGOR *
tpm2_get_pki1_algor(TPM2_ALG_ID digalg)
{
    X509_ALGOR* x509_algor;
    ASN1_OBJECT *oid;

    switch (digalg) {
    case TPM2_ALG_SHA1:
        oid = OBJ_nid2obj(NID_sha1WithRSAEncryption);
        break;
    case TPM2_ALG_SHA256:
        oid = OBJ_nid2obj(NID_sha256WithRSAEncryption);
        break;
    case TPM2_ALG_SHA384:
        oid = OBJ_nid2obj(NID_sha384WithRSAEncryption);
        break;
    case TPM2_ALG_SHA512:
        oid = OBJ_nid2obj(NID_sha512WithRSAEncryption);
        break;
    default:
        return NULL;
    }

    if ((x509_algor = X509_ALGOR_new()) == NULL)
        return NULL;
    X509_ALGOR_set0(x509_algor, oid, V_ASN1_NULL, NULL);

    return x509_algor;
}

X509_ALGOR *
tpm2_hash_to_x509(TPM2_ALG_ID digalg)
{
    ASN1_OBJECT *pssoid;
    X509_ALGOR *res;

    switch (digalg) {
    case TPM2_ALG_SHA1:
        pssoid = OBJ_nid2obj(NID_sha1);
        break;
    case TPM2_ALG_SHA256:
        pssoid = OBJ_nid2obj(NID_sha256);
        break;
    case TPM2_ALG_SHA384:
        pssoid = OBJ_nid2obj(NID_sha384);
        break;
    case TPM2_ALG_SHA512:
        pssoid = OBJ_nid2obj(NID_sha512);
        break;
    default:
        return NULL;
    }

    if ((res = X509_ALGOR_new()) == NULL)
        return NULL;
    if (X509_ALGOR_set0(res, pssoid, V_ASN1_NULL, NULL))
        return res;
error:
    X509_ALGOR_free(res);
    return NULL;
}

X509_ALGOR *
tpm2_mgf1_to_x509(TPM2_ALG_ID digalg)
{
    X509_ALGOR *algtmp, *res;
    ASN1_STRING *sres, *stmp = NULL;

    if ((algtmp = tpm2_hash_to_x509(digalg)) == NULL)
        return NULL;
    sres = ASN1_item_pack(algtmp, ASN1_ITEM_rptr(X509_ALGOR), &stmp);
    X509_ALGOR_free(algtmp);
    if (sres == NULL)
        return NULL;

    if ((res = X509_ALGOR_new()) != NULL
            && X509_ALGOR_set0(res, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, stmp))
        return res;

    X509_ALGOR_free(res);
    return NULL;
}

// As in Part 4, 10.2.17.4.13 CryptRsaPssSaltSize()
static int
CryptRsaPssSaltSize(int hashSize, int outSize)
{
    int saltSize;

    // (Mask Length) = (outSize - hashSize - 1);
    // Max saltSize is (Mask Length) - 1
    saltSize = (outSize - hashSize - 1) - 1;
    // Use the maximum salt size allowed by FIPS 186-4
    if(saltSize > hashSize)
        saltSize = hashSize;
    else if(saltSize < 0)
        saltSize = 0;
    return saltSize;
}

ASN1_INTEGER *
tpm2_pss_salt_length(int key_bits, TPM2_ALG_ID digalg)
{
    ASN1_INTEGER *res;
    int hashSize, outSize;

    switch (digalg) {
    case TPM2_ALG_SHA1:
        hashSize = TPM2_SHA1_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA256:
        hashSize = TPM2_SHA256_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA384:
        hashSize = TPM2_SHA384_DIGEST_SIZE;
        break;
    case TPM2_ALG_SHA512:
        hashSize = TPM2_SHA512_DIGEST_SIZE;
        break;
    default:
        return NULL;
    }

    outSize = (key_bits + 7) / 8;

    if ((res = ASN1_INTEGER_new()) == NULL)
        return NULL;

    if (ASN1_INTEGER_set(res, CryptRsaPssSaltSize(hashSize, outSize)))
        return res;

    ASN1_INTEGER_free(res);
    return NULL;
}

ASN1_STRING *
tpm2_get_rsapss_params(int key_bits, TPM2_ALG_ID digalg)
{
    RSA_PSS_PARAMS *pss;
    ASN1_STRING *parstr = NULL;

    if ((pss = RSA_PSS_PARAMS_new()) == NULL)
        return NULL;

    if ((pss->hashAlgorithm = tpm2_hash_to_x509(digalg)) == NULL
            || (pss->maskGenAlgorithm = tpm2_mgf1_to_x509(digalg)) == NULL
            || (pss->saltLength = tpm2_pss_salt_length(key_bits, digalg)) == NULL)
        goto end;

    if (!ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), &parstr))
        parstr = NULL;
end:
    RSA_PSS_PARAMS_free(pss);
    return parstr;
}

X509_ALGOR *
tpm2_get_rsapss_algor(int key_bits, TPM2_ALG_ID digalg)
{
    X509_ALGOR* x509_algor;
    ASN1_STRING *parstr;

    if ((x509_algor = X509_ALGOR_new()) == NULL)
        return NULL;

    if ((parstr = tpm2_get_rsapss_params(key_bits, digalg)) != NULL
            && X509_ALGOR_set0(x509_algor, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, parstr))
        return x509_algor;

    X509_ALGOR_free(x509_algor);
    return NULL;
}

/* build the DER-encoded X.509 AlgorithmIdentifier */
int
tpm2_sig_scheme_to_x509_alg(int key_bits, const TPMT_SIG_SCHEME *scheme,
                            unsigned char **aid, int *aid_size)
{
    X509_ALGOR* x509_algor;
    int len;

    if (scheme->scheme == TPM2_ALG_RSASSA) {
        if ((x509_algor = tpm2_get_pki1_algor(scheme->details.any.hashAlg)) == NULL)
            return 0;
    }
    else if (scheme->scheme == TPM2_ALG_RSAPSS) {
        if ((x509_algor = tpm2_get_rsapss_algor(key_bits, scheme->details.any.hashAlg)) == NULL)
            return 0;
    } else
        return 0;

    *aid_size = i2d_X509_ALGOR(x509_algor, aid);
    X509_ALGOR_free(x509_algor);

    return *aid_size > 0;
}

