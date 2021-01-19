/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 * Copyright (c) 2019, Wind River Systems.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <tss2/tss2_mu.h>

#include "tpm2-provider-pkey.h"

TPM2B_DIGEST ownerauth = { .size = 0 };
TPM2B_DIGEST parentauth = { .size = 0 };

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

BIO *
bio_new_from_core_bio(const BIO_METHOD *corebiometh, OSSL_CORE_BIO *corebio)
{
    BIO *outbio = NULL;

    if (corebiometh == NULL)
        return NULL;

    outbio = BIO_new(corebiometh);
    if (outbio != NULL)
        BIO_set_data(outbio, corebio);

    return outbio;
}

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

static TPM2B_PUBLIC primaryEccTemplate = TPM2B_PUBLIC_PRIMARY_ECC_TEMPLATE;
static TPM2B_PUBLIC primaryRsaTemplate = TPM2B_PUBLIC_PRIMARY_RSA_TEMPLATE;

static TPM2B_SENSITIVE_CREATE primarySensitive = {
    .sensitive = {
        .userAuth = {
             .size = 0,
         },
        .data = {
             .size = 0,
         }
    }
};

static TPM2B_DATA allOutsideInfo = {
    .size = 0,
};

static TPML_PCR_SELECTION allCreationPCR = {
    .count = 0,
};

/** Initialize the ESYS TPM connection and primary/persistent key
 *
 * Establish a connection with the TPM using ESYS libraries and create a primary
 * key under the owner hierarchy or to initialize the ESYS object for a
 * persistent if provided.
 * @param esys_ctx The resulting ESYS context.
 * @param parentHandle The TPM handle of a persistent key or TPM2_RH_OWNER or 0
 * @param parent The resulting ESYS_TR handle for the parent key.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RCs according to the error
 */
TSS2_RC
init_tpm_parent(TPM2_PKEY *pkey,
                TPM2_HANDLE parentHandle, ESYS_TR *parent)
{
    TSS2_RC r;
    TPM2B_PUBLIC *primaryTemplate = NULL;
    TPMS_CAPABILITY_DATA *capabilityData = NULL;
    UINT32 index;
    *parent = ESYS_TR_NONE;

    if (parentHandle && parentHandle != TPM2_RH_OWNER) {
        DBG("Connecting to a persistent parent key.\n");
        r = Esys_TR_FromTPMPublic(pkey->esys_ctx, parentHandle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  parent);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

        r = Esys_TR_SetAuth(pkey->esys_ctx, *parent, &parentauth);
        TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

        return TSS2_RC_SUCCESS;
    }

    DBG("Creating primary key under owner.\n");
    r = Esys_TR_SetAuth(pkey->esys_ctx, ESYS_TR_RH_OWNER, &ownerauth);
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    r = Esys_GetCapability(pkey->esys_ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_ALGS, 0, TPM2_MAX_CAP_ALGS,
                           NULL, &capabilityData);
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    for (index = 0; index < capabilityData->data.algorithms.count; index++) {
        if (capabilityData->data.algorithms.algProperties[index].alg == TPM2_ALG_ECC) {
            primaryTemplate = &primaryEccTemplate;
            break;
        }
    }

    if (primaryTemplate == NULL) {
        for (index = 0; index < capabilityData->data.algorithms.count; index++) {
            if (capabilityData->data.algorithms.algProperties[index].alg == TPM2_ALG_RSA) {
                primaryTemplate = &primaryRsaTemplate;
                break;
            }
        }
    }

    if (capabilityData != NULL)
        free (capabilityData);

    if (primaryTemplate == NULL) {
        TPM2_ERROR_raise(pkey, TPM2TSS_R_UNKNOWN_ALG);
        goto error;
    }

    r = Esys_CreatePrimary(pkey->esys_ctx, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &primarySensitive, primaryTemplate, &allOutsideInfo,
                           &allCreationPCR,
                           parent, NULL, NULL, NULL, NULL);
    if (r == 0x000009a2) {
        TPM2_ERROR_raise(pkey, TPM2TSS_R_OWNER_AUTH_FAILED);
        goto error;
    }
    TPM2_CHECK_RC(pkey, r, TPM2TSS_R_GENERAL_FAILURE, goto error);

    return TSS2_RC_SUCCESS;
 error:
    if (*parent != ESYS_TR_NONE)
        Esys_FlushContext(pkey->esys_ctx, *parent);
    *parent = ESYS_TR_NONE;

    return r;
}

