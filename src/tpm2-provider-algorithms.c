/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>

#include "tpm2-provider-algorithms.h"

TPMI_ALG_HASH
tpm2_name_to_alg_hash(const char *name)
{
    if (strcasecmp(name, "sha1") == 0)
        return TPM2_ALG_SHA1;
    else if (strcasecmp(name, "sha256") == 0)
        return TPM2_ALG_SHA256;
    else if (strcasecmp(name, "sha384") == 0)
        return TPM2_ALG_SHA384;
    else if (strcasecmp(name, "sha512") == 0)
        return TPM2_ALG_SHA512;
    else
        return TPM2_ALG_ERROR;
}

TPMI_ALG_RSA_SCHEME
tpm2_name_to_alg_rsa_scheme(const char *name)
{
    if (strcasecmp(name, "pkcs1") == 0)
        return TPM2_ALG_RSASSA;
    else if (strcasecmp(name, "pss") == 0)
        return TPM2_ALG_RSAPSS;
    else
        return TPM2_ALG_ERROR;
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
tpm2_get_pss_algor(const TPMT_SIG_SCHEME *scheme, TPM2_ALG_ID digalg)
{
    X509_ALGOR* x509_algor;
    RSA_PSS_PARAMS *pss;
    ASN1_OBJECT *pssoid;
    ASN1_STRING *parstr = NULL;

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
        goto error1;
    }

    if ((pss = RSA_PSS_PARAMS_new()) == NULL)
        goto error1;
    if ((pss->hashAlgorithm = X509_ALGOR_new()) == NULL)
        goto error2;

    if (!X509_ALGOR_set0(pss->hashAlgorithm, pssoid, V_ASN1_NULL, NULL) ||
            !ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), &parstr))
        goto error3;

    if ((x509_algor = X509_ALGOR_new()) == NULL)
        goto error3;

    X509_ALGOR_set0(x509_algor, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, parstr);

    return x509_algor;
error3:
    X509_ALGOR_free(pss->hashAlgorithm);
error2:
    RSA_PSS_PARAMS_free(pss);
error1:
    return NULL;
}

/* build the DER-encoded X.509 AlgorithmIdentifier */
int
tpm2_sig_scheme_to_x509_alg(const TPMT_SIG_SCHEME *scheme, TPM2_ALG_ID digalg,
                            unsigned char **aid, int *aid_size)
{
    X509_ALGOR* x509_algor;
    int len;

    if (scheme->scheme == TPM2_ALG_RSASSA) {
        if ((x509_algor = tpm2_get_pki1_algor(digalg)) == NULL)
            return 0;
    }
    else if (scheme->scheme == TPM2_ALG_RSAPSS) {
        if ((x509_algor = tpm2_get_pss_algor(scheme, digalg)) == NULL)
            return 0;
    } else
        return 0;

    *aid_size = i2d_X509_ALGOR(x509_algor, aid);
    X509_ALGOR_free(x509_algor);

    return *aid_size > 0;
}

