/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "tpm2-provider-pkey.h"
#include "tpm2-provider-types.h"
#include "tpm2-provider-x509.h"

typedef struct tpm2_encoder_ctx_st TPM2_ENCODER_CTX;

struct tpm2_encoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
};

static OSSL_FUNC_encoder_newctx_fn tpm2_encoder_newctx;
static OSSL_FUNC_encoder_freectx_fn tpm2_encoder_freectx;
static OSSL_FUNC_encoder_encode_fn tpm2_rsa_encoder_encode_text;
static OSSL_FUNC_encoder_encode_fn tpm2_ec_encoder_encode_text;

static void *
tpm2_encoder_newctx(void *provctx)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_ENCODER_CTX *ectx = OPENSSL_zalloc(sizeof(TPM2_ENCODER_CTX));

    if (ectx == NULL)
        return NULL;

    ectx->core = cprov->core;
    ectx->libctx = cprov->libctx;
    return ectx;
}

static void
tpm2_encoder_freectx(void *ctx)
{
    TPM2_ENCODER_CTX *ectx = ctx;

    if (ectx == NULL)
        return;

    OPENSSL_clear_free(ectx, sizeof(TPM2_ENCODER_CTX));
}

#define IMPLEMENT_ENCODER_DOES_SELECTION(otype, ostructure, oformat) \
    static OSSL_FUNC_encoder_does_selection_fn tpm2_##otype##_encoder_##ostructure##_##oformat##_does_selection; \
    static int \
    tpm2_##otype##_encoder_##ostructure##_##oformat##_does_selection(void *ctx, int selection) \
    { \
        DBG("ENCODER " #otype " " #ostructure "/" #oformat " DOES_SELECTION 0x%x\n", selection); \
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) { \
            return (tpm2_##otype##_encode_private_##ostructure##_##oformat != NULL); \
        } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) { \
            return (tpm2_##otype##_encode_public_##ostructure##_##oformat != NULL); \
        } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) { \
            return (tpm2_##otype##_encode_parameters_##ostructure##_##oformat != NULL); \
        } \
        return 0; \
    }

#define IMPLEMENT_ENCODER_ENCODE(otype, ostructure, oformat) \
    static OSSL_FUNC_encoder_encode_fn tpm2_##otype##_encoder_encode_##ostructure##_##oformat; \
    static int \
    tpm2_##otype##_encoder_encode_##ostructure##_##oformat(void *ctx, \
            OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], \
            int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) \
    { \
        TPM2_ENCODER_CTX *ectx = ctx; \
        TPM2_PKEY *pkey = (TPM2_PKEY *)key; \
        BIO *bout; \
        int ret = 0; \
\
        DBG("ENCODER " #otype " " #ostructure "/" #oformat " ENCODE 0x%x\n", selection); \
        if ((bout = BIO_new_from_core_bio(ectx->libctx, cout)) == NULL) \
            return 0; \
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) { \
            if (tpm2_##otype##_encode_private_##ostructure##_##oformat != NULL) \
                ret = tpm2_##otype##_encode_private_##ostructure##_##oformat(ectx, bout, pkey); \
        } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) { \
            if (tpm2_##otype##_encode_public_##ostructure##_##oformat != NULL) \
                ret = tpm2_##otype##_encode_public_##ostructure##_##oformat(ectx, bout, pkey); \
        } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) { \
            if (tpm2_##otype##_encode_parameters_##ostructure##_##oformat != NULL) \
                ret = tpm2_##otype##_encode_parameters_##ostructure##_##oformat(ectx, bout, pkey); \
        } \
        BIO_free(bout); \
        return ret; \
    }

#define IMPLEMENT_ENCODER_DISPATCH(otype, ostructure, oformat) \
    const OSSL_DISPATCH tpm2_##otype##_encoder_##ostructure##_##oformat##_functions[] = { \
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_encoder_newctx }, \
        { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_encoder_freectx }, \
        { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))tpm2_##otype##_encoder_##ostructure##_##oformat##_does_selection }, \
        { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_##otype##_encoder_encode_##ostructure##_##oformat }, \
        { 0, NULL } \
    };

#define DECLARE_ENCODER(otype, ostructure, oformat) \
    IMPLEMENT_ENCODER_DOES_SELECTION(otype, ostructure, oformat) \
    IMPLEMENT_ENCODER_ENCODE(otype, ostructure, oformat) \
    IMPLEMENT_ENCODER_DISPATCH(otype, ostructure, oformat)

typedef int (*tpm2_tss_encode_fun)(TPM2_ENCODER_CTX *, BIO *, TPM2_PKEY *);
#define NO_ENCODE ((tpm2_tss_encode_fun)NULL)


/* TSS2 PRIVATE KEY encoders */

static int
tpm2_tss_encode_private_PrivateKeyInfo_der(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    return tpm2_keydata_write(&pkey->data, bout, KEY_FORMAT_DER);
}

#define tpm2_tss_encode_public_PrivateKeyInfo_der NO_ENCODE
#define tpm2_tss_encode_parameters_PrivateKeyInfo_der NO_ENCODE

DECLARE_ENCODER(tss, PrivateKeyInfo, der)


static int
tpm2_tss_encode_private_PrivateKeyInfo_pem(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    return tpm2_keydata_write(&pkey->data, bout, KEY_FORMAT_PEM);
}

#define tpm2_tss_encode_public_PrivateKeyInfo_pem NO_ENCODE
#define tpm2_tss_encode_parameters_PrivateKeyInfo_pem NO_ENCODE

DECLARE_ENCODER(tss, PrivateKeyInfo, pem)


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
    if ((nbig = BN_bin2bn(pkey->data.pub.publicArea.unique.rsa.buffer,
                          pkey->data.pub.publicArea.unique.rsa.size, NULL)) == NULL
            || !BN_to_ASN1_INTEGER(nbig, tpk->n))
        goto error2;

    BN_free(nbig);

    /* set e */
    exponent = pkey->data.pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;

    // note the ASN1_INTEGER_set is not reliable for uin32_t on 32-bit machines
    if (!ASN1_INTEGER_set_uint64(tpk->e, exponent))
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

static int
tpm2_rsa_encode_public_pkcs1_der(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
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

#define tpm2_rsa_encode_private_pkcs1_der NO_ENCODE
#define tpm2_rsa_encode_parameters_pkcs1_der NO_ENCODE

DECLARE_ENCODER(rsa, pkcs1, der)


static int
tpm2_rsa_encode_public_pkcs1_pem(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
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

#define tpm2_rsa_encode_private_pkcs1_pem NO_ENCODE
#define tpm2_rsa_encode_parameters_pkcs1_pem NO_ENCODE

DECLARE_ENCODER(rsa, pkcs1, pem)


#define DECLARE_ENCODE_X509_PUBKEY_DER(type) \
    static int \
    tpm2_##type##_encode_public_SubjectPublicKeyInfo_der(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey) \
    { \
        X509_PUBKEY *pubkey; \
        int ret; \
\
        if ((pubkey = tpm2_get_x509_##type##_pubkey(pkey)) == NULL) \
            return 0; \
        ret = i2d_X509_PUBKEY_bio(bout, pubkey); \
        X509_PUBKEY_free(pubkey); \
        return ret; \
    }

#define DECLARE_ENCODE_X509_PUBKEY_PEM(type) \
    static int \
    tpm2_##type##_encode_public_SubjectPublicKeyInfo_pem(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey) \
    { \
        X509_PUBKEY *pubkey; \
        int ret; \
\
        if ((pubkey = tpm2_get_x509_##type##_pubkey(pkey)) == NULL) \
            return 0; \
        ret = PEM_write_bio_X509_PUBKEY(bout, pubkey); \
        X509_PUBKEY_free(pubkey); \
        return ret; \
    }

#define DECLARE_ENCODER_X509_PUBKEY(type) \
    DECLARE_ENCODE_X509_PUBKEY_DER(type) \
    DECLARE_ENCODER(type, SubjectPublicKeyInfo, der) \
    DECLARE_ENCODE_X509_PUBKEY_PEM(type) \
    DECLARE_ENCODER(type, SubjectPublicKeyInfo, pem)


static X509_PUBKEY *
tpm2_get_x509_rsa_pubkey(const TPM2_PKEY *pkey)
{
    unsigned char *penc = NULL;
    int penclen;
    X509_PUBKEY *pubkey;

    if ((penclen = tpm2_get_rsa_pubkey_der(pkey, &penc)) < 0)
        return NULL;

    if ((pubkey = X509_PUBKEY_new()) == NULL) {
        OPENSSL_free(penc);
        return NULL;
    }

    /* per RFC3279 the parameters must be NULL */
    X509_PUBKEY_set0_param(pubkey,
                           OBJ_nid2obj(NID_rsaEncryption),
                           V_ASN1_NULL, NULL, penc, penclen);
    return pubkey;
}

#define tpm2_rsa_encode_private_SubjectPublicKeyInfo_der NO_ENCODE
#define tpm2_rsa_encode_private_SubjectPublicKeyInfo_pem NO_ENCODE
#define tpm2_rsa_encode_parameters_SubjectPublicKeyInfo_der NO_ENCODE
#define tpm2_rsa_encode_parameters_SubjectPublicKeyInfo_pem NO_ENCODE

DECLARE_ENCODER_X509_PUBKEY(rsa)


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
    if ((params = tpm2_get_x509_rsapss_params(TPM2_PKEY_RSA_BITS(pkey),
                                              TPM2_PKEY_RSA_HASH(pkey))) == NULL)
        goto error2;

    /* per RFC4055 the parameters must be present */
    X509_PUBKEY_set0_param(pubkey,
                           OBJ_nid2obj(NID_rsassaPss),
                           V_ASN1_SEQUENCE, params, penc, penclen);
    return pubkey;
error2:
    OPENSSL_free(penc);
error1:
    X509_PUBKEY_free(pubkey);
    return NULL;
}

#define tpm2_rsapss_encode_private_SubjectPublicKeyInfo_der NO_ENCODE
#define tpm2_rsapss_encode_private_SubjectPublicKeyInfo_pem NO_ENCODE
#define tpm2_rsapss_encode_parameters_SubjectPublicKeyInfo_der NO_ENCODE
#define tpm2_rsapss_encode_parameters_SubjectPublicKeyInfo_pem NO_ENCODE

DECLARE_ENCODER_X509_PUBKEY(rsapss)


/* EC PUBLIC KEY encoders */

static X509_PUBKEY *
tpm2_get_x509_ec_pubkey(const TPM2_PKEY *pkey)
{
    X509_PUBKEY *pubkey;
    unsigned char *penc;
    int penclen;

    if ((pubkey = X509_PUBKEY_new()) == NULL)
        return NULL;

    if ((penclen = tpm2_ecc_point_to_uncompressed(
            &pkey->data.pub.publicArea.unique.ecc.x,
            &pkey->data.pub.publicArea.unique.ecc.y, (void **)&penc)) == 0)
        goto error1;

    /* per RFC5480 the parameter indicates the curve name */
    if (!X509_PUBKEY_set0_param(pubkey,
                                OBJ_nid2obj(NID_X9_62_id_ecPublicKey),
                                V_ASN1_OBJECT, OBJ_nid2obj(tpm2_ecc_curve_to_nid(
                                                    TPM2_PKEY_EC_CURVE(pkey))),
                                penc, penclen))
        goto error2;

    return pubkey;
error2:
    OPENSSL_free(penc);
error1:
    X509_PUBKEY_free(pubkey);
    return NULL;
}

static EC_GROUP *
get_ec_group(TPM2_PKEY *pkey)
{
    return EC_GROUP_new_by_curve_name(
                tpm2_ecc_curve_to_nid(TPM2_PKEY_EC_CURVE(pkey)));
}

static int
tpm2_ec_encode_parameters_SubjectPublicKeyInfo_der(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    EC_GROUP *group;
    int res;

    if ((group = get_ec_group(pkey)) == NULL)
        return 0;

    res = i2d_ECPKParameters_bio(bout, group);

    EC_GROUP_free(group);
    return res;
}

/* Public PEM_write_bio_ECPKParameters has been deprecated,
 * we need to implement its local version. */
IMPLEMENT_PEM_write_bio(myECPKParameters, EC_GROUP, PEM_STRING_ECPARAMETERS, ECPKParameters)

static int
tpm2_ec_encode_parameters_SubjectPublicKeyInfo_pem(TPM2_ENCODER_CTX *ectx, BIO *bout, TPM2_PKEY *pkey)
{
    EC_GROUP *group;
    int res;

    if ((group = get_ec_group(pkey)) == NULL)
        return 0;

    res = PEM_write_bio_myECPKParameters(bout, group);

    EC_GROUP_free(group);
    return res;
}

#define tpm2_ec_encode_private_SubjectPublicKeyInfo_der NO_ENCODE
#define tpm2_ec_encode_private_SubjectPublicKeyInfo_pem NO_ENCODE

DECLARE_ENCODER_X509_PUBKEY(ec)


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

static int
print_object_attributes(BIO *bout, TPMA_OBJECT objectAttributes)
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

    BIO_printf(bout, "Object Attributes:\n");
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (objectAttributes & tab[i].in)
            BIO_printf(bout, "  %s\n", tab[i].name);
    }

    return 0;
}

static int
tpm2_rsa_encoder_encode_text(void *ctx, OSSL_CORE_BIO *cout, const void *key,
        const OSSL_PARAM key_abstract[], int selection,
        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    TPM2_ENCODER_CTX *ectx = ctx;
    TPM2_PKEY *pkey = (TPM2_PKEY *)key;
    BIO *bout;
    UINT32 exponent;

    DBG("ENCODER ENCODE rsa text\n");

    bout = BIO_new_from_core_bio(ectx->libctx, cout);
    if (bout == NULL)
        return 0;

    BIO_printf(bout, "Private-Key: (RSA %i bit, TPM 2.0)\n",
        TPM2_PKEY_RSA_BITS(pkey));

    print_labeled_buf(bout, "Modulus:",
                      pkey->data.pub.publicArea.unique.rsa.buffer,
                      pkey->data.pub.publicArea.unique.rsa.size);

    exponent = pkey->data.pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;

    BIO_printf(bout, "Exponent: %i (0x%x)\n", exponent, exponent);

    print_object_attributes(bout, pkey->data.pub.publicArea.objectAttributes);

    BIO_printf(bout, "Signature Scheme: %s\n",
        tpm2_rsa_scheme_alg_to_name(TPM2_PKEY_RSA_SCHEME(pkey)));
    BIO_printf(bout, "  Hash: %s\n",
        tpm2_hash_alg_to_name(TPM2_PKEY_RSA_HASH(pkey)));

    BIO_free(bout);
    return 1;
}

const OSSL_DISPATCH tpm2_rsa_encoder_text_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_rsa_encoder_encode_text },
    { 0, NULL }
};

static int
tpm2_ec_encoder_encode_text(void *ctx, OSSL_CORE_BIO *cout, const void *key,
        const OSSL_PARAM key_abstract[], int selection,
        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    TPM2_ENCODER_CTX *ectx = ctx;
    TPM2_PKEY *pkey = (TPM2_PKEY *)key;
    BIO *bout;
    int curve_nid;
    size_t size;
    void *buffer;

    DBG("ENCODER ENCODE ec text\n");

    bout = BIO_new_from_core_bio(ectx->libctx, cout);
    if (bout == NULL)
        return 0;

    curve_nid = tpm2_ecc_curve_to_nid(TPM2_PKEY_EC_CURVE(pkey));
    BIO_printf(bout, "Private-Key: (EC %s, TPM 2.0)\n", EC_curve_nid2nist(curve_nid));

    size = tpm2_ecc_point_to_uncompressed(
                &pkey->data.pub.publicArea.unique.ecc.x,
                &pkey->data.pub.publicArea.unique.ecc.y, &buffer);

    print_labeled_buf(bout, "pub:", buffer, size);
    OPENSSL_free(buffer);

    BIO_printf(bout, "ASN1 OID: %s\n", OBJ_nid2sn(curve_nid));

    print_object_attributes(bout, pkey->data.pub.publicArea.objectAttributes);

    BIO_free(bout);
    return 1;
}

const OSSL_DISPATCH tpm2_ec_encoder_text_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_ec_encoder_encode_text },
    { 0, NULL }
};

