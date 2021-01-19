/*******************************************************************************
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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_rsa_encoder_ctx_st TPM2_RSA_ENCODER_CTX;

struct tpm2_rsa_encoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    BIO_METHOD *corebiometh;
};

static void *
tpm2_rsa_encoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RSA_ENCODER_CTX *ectx = OPENSSL_zalloc(sizeof(TPM2_RSA_ENCODER_CTX));

    DBG("ENCODER NEW\n");
    if (ectx == NULL)
        return NULL;

    ectx->core = cprov->core;
    ectx->corebiometh = cprov->corebiometh;
    return ectx;
}

static void
tpm2_rsa_encoder_freectx(void *ctx)
{
    TPM2_RSA_ENCODER_CTX *ectx = ctx;

    DBG("ENCODER FREE\n");
    OPENSSL_clear_free(ectx, sizeof(TPM2_RSA_ENCODER_CTX));
}

static const OSSL_PARAM *
tpm2_rsa_encoder_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}


/* Encoder for TSS2 PRIVATE KEY */

static int
tpm2_rsa_encoder_get_params_pkcs8_pem(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pem"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pkcs8"))
        return 0;

    return 1;
}

static int
tpm2_rsa_encoder_encode_pkcs8_pem(void *ctx, OSSL_CORE_BIO *cout, const void *key,
        const OSSL_PARAM key_abstract[], int selection,
        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    TPM2_RSA_ENCODER_CTX *ectx = ctx;
    TPM2_PKEY *pkey = (TPM2_PKEY *)key;
    BIO *bout;
    int ret;

    DBG("ENCODER ENCODE pkcs8/pem\n");
    bout = bio_new_from_core_bio(ectx->corebiometh, cout);
    if (bout == NULL)
        return 0;

    ret = tpm2_keydata_write(&pkey->data, bout);
    BIO_free(bout);

    return ret;
}

const OSSL_DISPATCH tpm2_rsa_encoder_pkcs8_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_rsa_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_rsa_encoder_freectx },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))tpm2_rsa_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_GET_PARAMS, (void (*)(void))tpm2_rsa_encoder_get_params_pkcs8_pem },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_rsa_encoder_encode_pkcs8_pem },
    { 0, NULL }
};


/* Encoder for PUBLIC KEY */

typedef struct {
    ASN1_INTEGER *n;
    ASN1_INTEGER *e;
} TPM2_RSA_PUBKEY;

ASN1_SEQUENCE(TPM2_RSA_PUBKEY) = {
    ASN1_SIMPLE(TPM2_RSA_PUBKEY, n, ASN1_INTEGER),
    ASN1_SIMPLE(TPM2_RSA_PUBKEY, e, ASN1_INTEGER),
} ASN1_SEQUENCE_END(TPM2_RSA_PUBKEY)

IMPLEMENT_ASN1_FUNCTIONS(TPM2_RSA_PUBKEY);


static int
tpm2_rsa_encoder_get_params_pubkey_pem(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pem"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "SubjectPublicKeyInfo"))
        return 0;

    return 1;
}

static int
tpm2_rsa_encoder_encode_pubkey_pem(void *ctx, OSSL_CORE_BIO *cout, const void *key,
        const OSSL_PARAM key_abstract[], int selection,
        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    TPM2_RSA_ENCODER_CTX *ectx = ctx;
    TPM2_PKEY *pkey = (TPM2_PKEY *)key;
    X509_PUBKEY *pubkey;
    unsigned char *penc = NULL;
    int penclen;
    BIO *bout;
    TPM2_RSA_PUBKEY *tpk;
    UINT32 exponent;
    BIGNUM *nbig;
    int ret;

    DBG("ENCODER ENCODE SubjectPublicKeyInfo/pem\n");
    tpk = TPM2_RSA_PUBKEY_new();
    if (!tpk)
        return 0;

    /* set n */
    tpk->n = ASN1_INTEGER_new();

    nbig = BN_bin2bn(pkey->data.pub.publicArea.unique.rsa.buffer,
                    pkey->data.pub.publicArea.unique.rsa.size, NULL);
    BN_to_ASN1_INTEGER(nbig, tpk->n);
    BN_free(nbig);

    /* set 2 */
    tpk->e = ASN1_INTEGER_new();

    exponent = pkey->data.pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;

    ASN1_INTEGER_set(tpk->e, exponent);

    /* export as DER */
    penclen = i2d_TPM2_RSA_PUBKEY(tpk, &penc);
    TPM2_RSA_PUBKEY_free(tpk);
    if (penclen < 0)
        return 0;

    bout = bio_new_from_core_bio(ectx->corebiometh, cout);
    if (bout == NULL)
        return 0;

    /* export X.509 PEM */
    pubkey = X509_PUBKEY_new();
    X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, NULL, penc, penclen);

    ret = PEM_write_bio_X509_PUBKEY(bout, pubkey);

    X509_PUBKEY_free(pubkey);
    BIO_free(bout);

    return ret;
}

const OSSL_DISPATCH tpm2_rsa_encoder_pubkey_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_rsa_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_rsa_encoder_freectx },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))tpm2_rsa_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_GET_PARAMS, (void (*)(void))tpm2_rsa_encoder_get_params_pubkey_pem },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_rsa_encoder_encode_pubkey_pem },
    { 0, NULL }
};

