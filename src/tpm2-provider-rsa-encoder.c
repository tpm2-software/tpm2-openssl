/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-algorithms.h"
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

    if (ectx == NULL)
        return;

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

static int
tpm2_rsa_encoder_get_params_int(OSSL_PARAM params[],
                                const char *otype, const char *ostructure)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, otype))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ostructure))
        return 0;

    return 1;
};

#define IMPLEMENT_ENCODER_GET_PARAMS(otype, ostructure, oformat) \
    static int \
    tpm2_##otype##_encoder_get_params_##ostructure##_##oformat(OSSL_PARAM params[]) \
    { \
        TRACE_PARAMS("ENCODER " #otype " " #ostructure "/" #oformat " GET_PARAMS", params); \
        return tpm2_rsa_encoder_get_params_int(params, #oformat, #ostructure); \
    }

#define IMPLEMENT_ENCODER_ENCODE(otype, ostructure, oformat) \
    static int \
    tpm2_##otype##_encoder_encode_##ostructure##_##oformat(void *ctx, \
            OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], \
            int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) \
    { \
        TPM2_RSA_ENCODER_CTX *ectx = ctx; \
        TPM2_PKEY *pkey = (TPM2_PKEY *)key; \
        BIO *bout; \
        int ret; \
\
        DBG("ENCODER " #otype " " #ostructure "/" #oformat " ENCODE\n"); \
        if ((bout = bio_new_from_core_bio(ectx->corebiometh, cout)) == NULL) \
            return 0; \
        ret = tpm2_##otype##_encode_##ostructure##_##oformat(ectx, bout, pkey); \
        BIO_free(bout); \
        return ret; \
    }

#define IMPLEMENT_ENCODER_DISPATCH(otype, ostructure, oformat) \
    const OSSL_DISPATCH tpm2_##otype##_encoder_##ostructure##_##oformat##_functions[] = { \
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_rsa_encoder_newctx }, \
        { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_rsa_encoder_freectx }, \
        { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))tpm2_rsa_encoder_gettable_params }, \
        { OSSL_FUNC_ENCODER_GET_PARAMS, (void (*)(void))tpm2_##otype##_encoder_get_params_##ostructure##_##oformat }, \
        { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_##otype##_encoder_encode_##ostructure##_##oformat }, \
        { 0, NULL } \
    };

#define DECLARE_ENCODER(otype, ostructure, oformat) \
    IMPLEMENT_ENCODER_GET_PARAMS(otype, ostructure, oformat) \
    IMPLEMENT_ENCODER_ENCODE(otype, ostructure, oformat) \
    IMPLEMENT_ENCODER_DISPATCH(otype, ostructure, oformat)


/* RSA PRIVATE KEY encoders */

static int
tpm2_rsa_encode_pkcs8_der(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    return tpm2_keydata_write(&pkey->data, bout, KEY_FORMAT_DER);
}

DECLARE_ENCODER(rsa, pkcs8, der)

static int
tpm2_rsa_encode_pkcs8_pem(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    return tpm2_keydata_write(&pkey->data, bout, KEY_FORMAT_PEM);
}

DECLARE_ENCODER(rsa, pkcs8, pem)


/* RSA PUBLIC KEY encoders */

typedef struct {
    ASN1_INTEGER *n;
    ASN1_INTEGER *e;
} TPM2_RSA_PUBKEY;

ASN1_SEQUENCE(TPM2_RSA_PUBKEY) = {
    ASN1_SIMPLE(TPM2_RSA_PUBKEY, n, ASN1_INTEGER),
    ASN1_SIMPLE(TPM2_RSA_PUBKEY, e, ASN1_INTEGER),
} ASN1_SEQUENCE_END(TPM2_RSA_PUBKEY)

IMPLEMENT_ASN1_FUNCTIONS(TPM2_RSA_PUBKEY);
IMPLEMENT_PEM_write_bio(TPM2_RSA_PUBKEY, TPM2_RSA_PUBKEY, PEM_STRING_RSA_PUBLIC, TPM2_RSA_PUBKEY);


static TPM2_RSA_PUBKEY *
tpm2_get_rsa_pubkey(const TPM2_PKEY *pkey)
{
    TPM2_RSA_PUBKEY *tpk;
    BIGNUM *nbig;
    UINT32 exponent;

    if ((tpk = TPM2_RSA_PUBKEY_new()) == NULL)
        goto error1;

    /* set n */
    if ((tpk->n = ASN1_INTEGER_new()) == NULL)
        goto error2;

    if ((nbig = BN_bin2bn(pkey->data.pub.publicArea.unique.rsa.buffer,
                          pkey->data.pub.publicArea.unique.rsa.size, NULL)) == NULL
            || !BN_to_ASN1_INTEGER(nbig, tpk->n))
        goto error2;

    BN_free(nbig);

    /* set e */
    exponent = pkey->data.pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;

    if ((tpk->e = ASN1_INTEGER_new()) == NULL
            || !ASN1_INTEGER_set(tpk->e, exponent))
        goto error2;

    return tpk;
error2:
    TPM2_RSA_PUBKEY_free(tpk);
error1:
    return NULL;
}

int
tpm2_get_rsa_pubkey_der(const TPM2_PKEY *pkey, unsigned char **penc)
{
    TPM2_RSA_PUBKEY *tpk;
    int penclen;

    if ((tpk = tpm2_get_rsa_pubkey(pkey)) == NULL)
        return -1;
    /* export as DER */
    penclen = i2d_TPM2_RSA_PUBKEY(tpk, penc);
    TPM2_RSA_PUBKEY_free(tpk);

    return penclen;
}

static X509_PUBKEY *
tpm2_get_x509_rsa_pubkey(const TPM2_PKEY *pkey)
{
    unsigned char *penc = NULL;
    int penclen;
    X509_PUBKEY *pubkey;

    if ((penclen = tpm2_get_rsa_pubkey_der(pkey, &penc)) < 0)
        return NULL;

    if ((pubkey = X509_PUBKEY_new()) == NULL) {
        free(penc);
        return NULL;
    }

    /* per RFC3279 the parameters must be NULL */
    X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, NULL, penc, penclen);
    return pubkey;
}

static X509_PUBKEY *
tpm2_get_x509_rsapss_pubkey(const TPM2_PKEY *pkey)
{
    X509_PUBKEY *pubkey;
    ASN1_STRING *params;
    unsigned char *penc = NULL;
    int penclen;

    if ((pubkey = X509_PUBKEY_new()) == NULL)
        return NULL;

    if ((penclen = tpm2_get_rsa_pubkey_der(pkey, &penc)) < 0)
        goto error1;
    if ((params = tpm2_get_rsapss_params(TPM2_PKEY_BITS(pkey), TPM2_PKEY_RSA_HASH(pkey))) == NULL)
        goto error2;

    /* per RFC4055 the parameters must be present */
    X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, params, penc, penclen);
    return pubkey;
error2:
    free(penc);
error1:
    X509_PUBKEY_free(pubkey);
    return NULL;
}

static int
tpm2_rsa_encode_pkcs1_der(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    TPM2_RSA_PUBKEY *tpk;
    int ret;

    if ((tpk = tpm2_get_rsa_pubkey(pkey)) == NULL)
        return 0;
    /* export as DER */
    ret = ASN1_item_i2d_bio(ASN1_ITEM_rptr(TPM2_RSA_PUBKEY), bout, tpk);

    TPM2_RSA_PUBKEY_free(tpk);
    return ret;
}

DECLARE_ENCODER(rsa, pkcs1, der)


static int
tpm2_rsa_encode_pkcs1_pem(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    TPM2_RSA_PUBKEY *tpk;
    int ret;

    if ((tpk = tpm2_get_rsa_pubkey(pkey)) == NULL)
        return 0;
    /* export as PEM */
    ret = PEM_write_bio_TPM2_RSA_PUBKEY(bout, tpk);

    TPM2_RSA_PUBKEY_free(tpk);
    return ret;
}

DECLARE_ENCODER(rsa, pkcs1, pem)


static int
tpm2_rsa_encode_SubjectPublicKeyInfo_der(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    X509_PUBKEY *pubkey;
    int ret;

    if ((pubkey = tpm2_get_x509_rsa_pubkey(pkey)) == NULL)
        return 0;
    /* export X.509 DER */
    ret = i2d_X509_PUBKEY_bio(bout, pubkey);

    X509_PUBKEY_free(pubkey);
    return ret;
}

DECLARE_ENCODER(rsa, SubjectPublicKeyInfo, der)


static int
tpm2_rsa_encode_SubjectPublicKeyInfo_pem(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    X509_PUBKEY *pubkey;
    int ret;

    if ((pubkey = tpm2_get_x509_rsa_pubkey(pkey)) == NULL)
        return 0;
    /* export X.509 PEM */
    ret = PEM_write_bio_X509_PUBKEY(bout, pubkey);

    X509_PUBKEY_free(pubkey);
    return ret;
}

DECLARE_ENCODER(rsa, SubjectPublicKeyInfo, pem)


static int
tpm2_rsapss_encode_SubjectPublicKeyInfo_der(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    X509_PUBKEY *pubkey;
    int ret;

    if ((pubkey = tpm2_get_x509_rsapss_pubkey(pkey)) == NULL)
        return 0;
    /* export X.509 DER */
    ret = i2d_X509_PUBKEY_bio(bout, pubkey);

    X509_PUBKEY_free(pubkey);
    return ret;
}

DECLARE_ENCODER(rsapss, SubjectPublicKeyInfo, der)


static int
tpm2_rsapss_encode_SubjectPublicKeyInfo_pem(TPM2_RSA_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    X509_PUBKEY *pubkey;
    int ret;

    if ((pubkey = tpm2_get_x509_rsapss_pubkey(pkey)) == NULL)
        return 0;
    /* export X.509 PEM */
    ret = PEM_write_bio_X509_PUBKEY(bout, pubkey);

    X509_PUBKEY_free(pubkey);
    return ret;
}

DECLARE_ENCODER(rsapss, SubjectPublicKeyInfo, pem)


/* RSA TEXT encoder */

/* Number of octets per line */
#define LABELED_BUF_PRINT_WIDTH    15

/* buffer must be in BIG endian */
static int print_labeled_buf(BIO *out, const char *label,
                             const unsigned char *buf, size_t buflen)
{
    size_t i, pos;

    if (BIO_printf(out, "%s\n", label) <= 0)
        return 0;

    pos = 0;
    /* Add a leading 00 if the top bit is set */
    if (buflen > 0 && *buf & 0x80) {
        if (BIO_printf(out, "    %02x%s", 0, buflen == 1 ? "" : ":") <= 0)
            return 0;
        pos++;
    }

    for (i = 0; i < buflen; i++, pos++) {
        if ((pos % LABELED_BUF_PRINT_WIDTH) == 0) {
            if (pos > 0 && BIO_printf(out, "\n") <= 0)
                return 0;
            if (BIO_printf(out, "    ") <= 0)
                return 0;
        }

        if (BIO_printf(out, "%02x%s", buf[i],
                       (i == buflen - 1) ? "" : ":") <= 0)
            return 0;
    }
    if (BIO_printf(out, "\n") <= 0)
        return 0;

    return 1;
}

static const OSSL_PARAM *
tpm2_rsa_encoder_gettable_params_text(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int
tpm2_rsa_encoder_get_params_text(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    TRACE_PARAMS("ENCODER GET_PARAMS", params);
    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "text"))
        return 0;

    return 1;
}

static int
tpm2_rsa_encoder_encode_text(void *ctx, OSSL_CORE_BIO *cout, const void *key,
        const OSSL_PARAM key_abstract[], int selection,
        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct { TPMA_OBJECT in; char *name; } tab[] = {
        { TPMA_OBJECT_FIXEDTPM, "fixedTPM" },
        { TPMA_OBJECT_STCLEAR, "stClear" },
        { TPMA_OBJECT_FIXEDPARENT, "fixedParent" },
        { TPMA_OBJECT_SENSITIVEDATAORIGIN, "sensitiveDataOrigin" },
        { TPMA_OBJECT_USERWITHAUTH, "userWithAuth" },
        { TPMA_OBJECT_ADMINWITHPOLICY, "adminWithPolicy" },
        { TPMA_OBJECT_NODA, "noDA" },
        { TPMA_OBJECT_ENCRYPTEDDUPLICATION, "encryptedDuplication" },
        { TPMA_OBJECT_RESTRICTED, "restricted" },
        { TPMA_OBJECT_DECRYPT, "decrypt" },
        { TPMA_OBJECT_SIGN_ENCRYPT, "sign / encrypt" },
    };
    TPM2_RSA_ENCODER_CTX *ectx = ctx;
    TPM2_PKEY *pkey = (TPM2_PKEY *)key;
    BIO *bout;
    UINT32 exponent;

    DBG("ENCODER ENCODE text\n");

    bout = bio_new_from_core_bio(ectx->corebiometh, cout);
    if (bout == NULL)
        return 0;

    BIO_printf(bout, "Private-Key: (%i bit, TPM 2.0)\n", TPM2_PKEY_BITS(pkey));

    print_labeled_buf(bout, "Modulus:",
                      pkey->data.pub.publicArea.unique.rsa.buffer,
                      pkey->data.pub.publicArea.unique.rsa.size);

    exponent = pkey->data.pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;

    BIO_printf(bout, "Exponent: %i (0x%x)\n", exponent, exponent);

    BIO_printf(bout, "Object Attributes:\n");
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (pkey->data.pub.publicArea.objectAttributes & tab[i].in)
            BIO_printf(bout, "  %s\n", tab[i].name);
    }

    BIO_printf(bout, "Signature Scheme: %s\n",
        tpm2_rsa_scheme_alg_to_name(TPM2_PKEY_RSA_SCHEME(pkey)));
    BIO_printf(bout, "  Hash: %s\n",
        tpm2_hash_alg_to_name(TPM2_PKEY_RSA_HASH(pkey)));

    BIO_free(bout);
    return 1;
}

const OSSL_DISPATCH tpm2_rsa_encoder_text_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_rsa_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_rsa_encoder_freectx },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS, (void (*)(void))tpm2_rsa_encoder_gettable_params_text },
    { OSSL_FUNC_ENCODER_GET_PARAMS, (void (*)(void))tpm2_rsa_encoder_get_params_text },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_rsa_encoder_encode_text },
    { 0, NULL }
};

