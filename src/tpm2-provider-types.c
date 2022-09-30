/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#include "tpm2-provider.h"
#include "tpm2-provider-types.h"

#ifdef _MSC_VER 
//not #if defined(_WIN32) || defined(_WIN64) because we have strncasecmp in mingw
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

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
tpm2_hash_name_to_alg(const TPMS_CAPABILITY_DATA *caps, const char *name)
{
    const hash_names_t *nameptr;

    for (nameptr = hashes; nameptr->name != NULL; nameptr++) {
        if (!strcasecmp(name, nameptr->name)) {
            /* do not accept unsupported algorithms */
            if (tpm2_supports_algorithm(caps, nameptr->alg))
                return nameptr->alg;
            else
                return TPM2_ALG_ERROR;
        }
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
    case RSA_PKCS1_PADDING:
        return TPM2_ALG_RSASSA;
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

typedef struct {
    int nid;
    TPM2_ECC_CURVE curve;
} curve_nids_t;

static const curve_nids_t curves[] = {
    { NID_X9_62_prime192v1, TPM2_ECC_NIST_P192 },
    { NID_secp224r1, TPM2_ECC_NIST_P224 },
    { NID_X9_62_prime256v1, TPM2_ECC_NIST_P256 },
    { NID_secp384r1, TPM2_ECC_NIST_P384 },
    { NID_secp521r1, TPM2_ECC_NIST_P521 },
    { NID_undef, TPM2_ECC_NONE }
};

TPM2_ECC_CURVE
tpm2_nid_to_ecc_curve(int nid)
{
    const curve_nids_t *nidptr;

    for (nidptr = curves; nidptr->nid != NID_undef; nidptr++) {
        if (nid == nidptr->nid)
            return nidptr->curve;
    }

    return TPM2_ECC_NONE;
}

int
tpm2_ecc_curve_to_nid(const TPM2_ECC_CURVE curve)
{
    const curve_nids_t *nidptr;

    for (nidptr = curves; nidptr->nid != NID_undef; nidptr++) {
        if (curve == nidptr->curve)
            return nidptr->nid;
    }

    return NID_undef;
}

TPM2_ECC_CURVE
tpm2_name_to_ecc_curve(const char* name)
{
    int nid;

    nid = EC_curve_nist2nid(name);
    if (nid == NID_undef)
        nid = OBJ_sn2nid(name);

    if (nid == NID_undef)
        return TPM2_ECC_NONE;
    else
        return tpm2_nid_to_ecc_curve(nid);
}

/* ECC point format per SEC1, section 2.3.3 */
size_t
tpm2_ecc_point_to_uncompressed(const TPM2B_ECC_PARAMETER *x,
                               const TPM2B_ECC_PARAMETER *y, void **buffer)
{
    size_t size;
    unsigned char *out;

    if (x == NULL || y == NULL)
        return 0;
    size = 1 + x->size + y->size;

    if ((*buffer = OPENSSL_malloc(size)) == NULL)
        return 0;
    out = (unsigned char *)*buffer;

    *(out++) = 4; /* form = uncompressed */
    memcpy(out, x->buffer, x->size);
    out += x->size;
    memcpy(out, y->buffer, y->size);
    return size;
}

/* We cannot prevent others from sending us the compressed point format,
 * hence we need a full-blown implementation.
 */
int
tpm2_buffer_to_ecc_point(int curve_nid, const unsigned char *buf, size_t len, TPMS_ECC_POINT *point)
{
    EC_GROUP *group = NULL;
    EC_POINT *pt = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int tolen, res = 0;

    if ((group = EC_GROUP_new_by_curve_name(curve_nid)) == NULL
            || (pt = EC_POINT_new(group)) == NULL
            || !EC_POINT_oct2point(group, pt, buf, len, NULL)
            || (x = BN_new()) == NULL
            || (y = BN_new()) == NULL
            || !EC_POINT_get_affine_coordinates(group, pt, x, y, NULL))
        goto final;

    /* TPM2 will check the length, expecting padded numbers */
    tolen = (EC_GROUP_order_bits(group) + 7) / 8;

    if (BN_bn2binpad(x, point->x.buffer, tolen) != tolen)
        goto final;
    point->x.size = tolen;

    if (BN_bn2binpad(y, point->y.buffer, tolen) != tolen)
        goto final;
    point->y.size = tolen;

    res = 1;
final:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(pt);
    EC_GROUP_free(group);
    return res;
}

int
tpm2_ecdsa_size(int curve_nid)
{
    EC_GROUP *group = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *bn;
    int ret;

    if ((group = EC_GROUP_new_by_curve_name(curve_nid)) == NULL
            || (bn = EC_GROUP_get0_order(group)) == NULL
            || (sig = ECDSA_SIG_new()) == NULL
            || !ECDSA_SIG_set0(sig, BN_dup(bn), BN_dup(bn))
            || (ret = i2d_ECDSA_SIG(sig, NULL)) < 0)
        ret = 0;

    ECDSA_SIG_free(sig);
    EC_GROUP_free(group);
    return ret;
}

int
tpm2_param_get_DIGEST(const OSSL_PARAM *p, TPM2B_DIGEST *digest)
{
    if (p->data_type != OSSL_PARAM_UTF8_STRING
            || p->data_size > sizeof(TPMU_HA))
        return 0;

    digest->size = p->data_size;
    memcpy(&digest->buffer, p->data, p->data_size);
    return 1;
}

int
tpm2_param_set_BN_from_buffer_size(OSSL_PARAM *p, const BYTE *buffer, UINT16 size)
{
    int res;
    BIGNUM *bignum = BN_bin2bn(buffer, size, NULL);

    res = OSSL_PARAM_set_BN(p, bignum);
    BN_free(bignum);
    return res;
}

int
tpm2_param_set_BN_from_uint32(OSSL_PARAM *p, UINT32 num)
{
    int res;
    BIGNUM *bignum = BN_new();

    BN_set_word(bignum, num);
    res = OSSL_PARAM_set_BN(p, bignum);
    BN_free(bignum);
    return res;
}

void *
revmemcpy(void *dest, const void *src, size_t len)
{
    char *d = dest + len - 1;
    const char *s = src;
    while (len--)
        *d-- = *s++;
    return dest;
}

