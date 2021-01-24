/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <tss2/tss2_mu.h>

#include "tpm2-provider-pkey.h"

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY;

ASN1_SEQUENCE(TSSPRIVKEY) = {
    ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
    ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
    ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
    ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)

#define OID_loadableKey "2.23.133.10.1.3"
#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY);
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);

/** Serialize TPM2_KEYDATA onto disk
 *
 * Write the tpm2tss key data into a file using PEM encoding.
 * @param tpm2Data The data to be written to disk.
 * @param filename The filename to write the data to.
 * @retval 1 on success
 * @retval 0 on failure
 */
int
tpm2_keydata_write(const TPM2_KEYDATA *keydata, BIO *bout)
{
    TSSPRIVKEY *tpk = NULL;
    TSS2_RC r;

    uint8_t privbuf[sizeof(keydata->priv)];
    uint8_t pubbuf[sizeof(keydata->pub)];
    size_t privbuf_len = 0, pubbuf_len = 0;

    tpk = TSSPRIVKEY_new();
    if (!tpk)
        return 0;

    if (Tss2_MU_TPM2B_PRIVATE_Marshal(&keydata->priv, &privbuf[0],
                                      sizeof(privbuf), &privbuf_len))
        goto error;

    if (Tss2_MU_TPM2B_PUBLIC_Marshal(&keydata->pub, &pubbuf[0],
                                     sizeof(pubbuf), &pubbuf_len))
        goto error;

    tpk->type = OBJ_txt2obj(OID_loadableKey, 1);
    tpk->parent = ASN1_INTEGER_new();
    tpk->privkey = ASN1_OCTET_STRING_new();
    tpk->pubkey = ASN1_OCTET_STRING_new();
    if (!tpk->type || !tpk->privkey || !tpk->pubkey || !tpk->parent)
        goto error;

    tpk->emptyAuth = ! !keydata->emptyAuth;
    if (keydata->parent != 0)
        ASN1_INTEGER_set(tpk->parent, keydata->parent);
    else
        ASN1_INTEGER_set(tpk->parent, TPM2_RH_OWNER);

    ASN1_STRING_set(tpk->privkey, &privbuf[0], privbuf_len);
    ASN1_STRING_set(tpk->pubkey, &pubbuf[0], pubbuf_len);

    PEM_write_bio_TSSPRIVKEY(bout, tpk);

    TSSPRIVKEY_free(tpk);
    return 1;
error:
    TSSPRIVKEY_free(tpk);
    return 0;
}

/** Deserialize TPM2_KEYDATA from disk
 *
 * Read the tpm2tss key data from a file using PEM encoding.
 * @param filename The filename to read the data from.
 * @param tpm2Datap The data after read.
 * @retval 1 on success
 * @retval 0 on EOF
 * @retval -1 on failure
 */
int
tpm2_keydata_read(BIO *bin, TPM2_KEYDATA *keydata)
{
    TSSPRIVKEY *tpk = NULL;
    char type_oid[64];

    tpk = PEM_read_bio_TSSPRIVKEY(bin, NULL, NULL, NULL);
    if (!tpk) {
        unsigned long last = ERR_peek_error();
        if (ERR_GET_REASON(last) == PEM_R_NO_START_LINE) {
            ERR_clear_error();
            return 0; /* no more data */
        } else
            return -1; /* some other error */
    }

    keydata->privatetype = KEY_TYPE_BLOB;
    keydata->emptyAuth = tpk->emptyAuth;

    keydata->parent = ASN1_INTEGER_get(tpk->parent);
    if (keydata->parent == 0)
        keydata->parent = TPM2_RH_OWNER;

    if (!OBJ_obj2txt(type_oid, sizeof(type_oid), tpk->type, 1) ||
            strcmp(type_oid, OID_loadableKey))
        goto error;

    if (Tss2_MU_TPM2B_PRIVATE_Unmarshal(tpk->privkey->data,
                                        tpk->privkey->length, NULL,
                                        &keydata->priv))
        goto error;

    if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(tpk->pubkey->data,
                                       tpk->pubkey->length, NULL,
                                       &keydata->pub))
        goto error;

    TSSPRIVKEY_free(tpk);
    return 1;
 error:
    TSSPRIVKEY_free(tpk);
    return -1;
}

static const TPM2B_PUBLIC primaryRsaTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_NODA |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN),
        .authPolicy = {
             .size = 0,
         },
        .parameters.rsaDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_AES,
                 .keyBits.aes = 128,
                 .mode.aes = TPM2_ALG_CFB,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .keyBits = 2048,
             .exponent = 0,
         },
        .unique.rsa = {
             .size = 0,
         }
     }
};

static const TPM2B_PUBLIC primaryEccTemplate = {
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_NODA |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN),
        .authPolicy = {
             .size = 0,
         },
        .parameters.eccDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_AES,
                 .keyBits.aes = 128,
                 .mode.aes = TPM2_ALG_CFB,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .curveID = TPM2_ECC_NIST_P256,
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

static const TPM2B_SENSITIVE_CREATE primarySensitive = {
    .sensitive = {
        .userAuth = {
             .size = 0,
         },
        .data = {
             .size = 0,
         }
    }
};

static const TPM2B_DATA allOutsideInfo = {
    .size = 0,
};

static const TPML_PCR_SELECTION allCreationPCR = {
    .count = 0,
};

int
tpm2_load_parent(TPM2_PKEY *pkey, TPM2_HANDLE handle,
                 const TPM2B_DIGEST *auth, ESYS_TR *object)
{
    TSS2_RC r;

    r = Esys_TR_FromTPMPublic(pkey->esys_ctx, handle,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              object);
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error1);

    r = Esys_TR_SetAuth(pkey->esys_ctx, *object, auth);
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error2);

    return 1;
error2:
    Esys_FlushContext(pkey->esys_ctx, *object);
error1:
    return 0;
}

static int
tpm2_supports_algorithm(const TPMS_CAPABILITY_DATA *caps, TPM2_ALG_ID algorithm)
{
    UINT32 index;

    for (index = 0; index < caps->data.algorithms.count; index++) {
        if (caps->data.algorithms.algProperties[index].alg == algorithm)
            return 1;
    }

    return 0;
}

int
tpm2_build_primary(TPM2_PKEY *pkey, ESYS_TR hierarchy,
                   const TPM2B_DIGEST *auth, ESYS_TR *object)
{
    TPMS_CAPABILITY_DATA *capabilityData = NULL;
    const TPM2B_PUBLIC *primaryTemplate = NULL;
    TSS2_RC r;

    r = Esys_TR_SetAuth(pkey->esys_ctx, hierarchy, auth);
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    r = Esys_GetCapability(pkey->esys_ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_ALGS, 0, TPM2_MAX_CAP_ALGS,
                           NULL, &capabilityData);
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    if (tpm2_supports_algorithm(capabilityData, TPM2_ALG_ECC))
        primaryTemplate = &primaryEccTemplate;
    else if (tpm2_supports_algorithm(capabilityData, TPM2_ALG_RSA))
        primaryTemplate = &primaryRsaTemplate;

    free(capabilityData);

    if(!primaryTemplate) {
        TPM2_ERROR_raise(pkey, TPM2TSS_R_UNKNOWN_ALG);
        goto error;
    }

    r = Esys_CreatePrimary(pkey->esys_ctx, hierarchy,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &primarySensitive, primaryTemplate, &allOutsideInfo,
                           &allCreationPCR,
                           object, NULL, NULL, NULL, NULL);
    if (r == 0x000009a2) {
        TPM2_ERROR_raise(pkey, TPM2TSS_R_OWNER_AUTH_FAILED);
        goto error;
    }
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    return 1;
error:
    return 0;
}

