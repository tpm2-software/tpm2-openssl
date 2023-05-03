/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/rsa.h>

#include "tpm2-provider-x509.h"

/* RSA (RSA-SSA) keys */

X509_ALGOR *
tpm2_get_pkcs1_algor(TPM2_ALG_ID digalg)
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


/* RSA-PSS keys */

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
tpm2_get_x509_rsapss_params(int key_bits, TPM2_ALG_ID digalg)
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

    if ((parstr = tpm2_get_x509_rsapss_params(key_bits, digalg)) != NULL
            && X509_ALGOR_set0(x509_algor, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, parstr))
        return x509_algor;

    X509_ALGOR_free(x509_algor);
    return NULL;
}


/* EC keys */

X509_ALGOR *
tpm2_get_ecdsa_algor(TPM2_ALG_ID digalg)
{
    X509_ALGOR* x509_algor;
    ASN1_OBJECT *oid;

    switch (digalg) {
    case TPM2_ALG_SHA1:
        oid = OBJ_nid2obj(NID_ecdsa_with_SHA1);
        break;
    case TPM2_ALG_SHA256:
        oid = OBJ_nid2obj(NID_ecdsa_with_SHA256);
        break;
    case TPM2_ALG_SHA384:
        oid = OBJ_nid2obj(NID_ecdsa_with_SHA384);
        break;
    case TPM2_ALG_SHA512:
        oid = OBJ_nid2obj(NID_ecdsa_with_SHA512);
        break;
    default:
        return NULL;
    }

    if ((x509_algor = X509_ALGOR_new()) == NULL)
        return NULL;
    X509_ALGOR_set0(x509_algor, oid, V_ASN1_NULL, NULL);

    return x509_algor;
}


/* build the DER-encoded X.509 AlgorithmIdentifier */
int
tpm2_sig_scheme_to_x509_alg(const TPMT_SIG_SCHEME *scheme, const TPMU_PUBLIC_PARMS *params,
                            unsigned char **aid, int *aid_size)
{
    X509_ALGOR* x509_algor;

    if (scheme->scheme == TPM2_ALG_RSASSA) {
        if ((x509_algor = tpm2_get_pkcs1_algor(scheme->details.any.hashAlg)) == NULL)
            return 0;
    }
    else if (scheme->scheme == TPM2_ALG_RSAPSS) {
        if ((x509_algor = tpm2_get_rsapss_algor(params->rsaDetail.keyBits,
                                                scheme->details.any.hashAlg)) == NULL)
            return 0;
    } else if (scheme->scheme == TPM2_ALG_ECDSA) {
        if ((x509_algor = tpm2_get_ecdsa_algor(scheme->details.any.hashAlg)) == NULL)
            return 0;
    } else
        return 0;

    *aid_size = i2d_X509_ALGOR(x509_algor, aid);
    X509_ALGOR_free(x509_algor);

    return *aid_size > 0;
}

