/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_TYPES_H
#define TPM2_PROVIDER_TYPES_H

#include <string.h>

#include <openssl/params.h>

#include <tss2/tss2_tpm2_types.h>

#define BUFFER_CMP(b1,b2) (b1.size != b2.size || memcmp(&b1.buffer, &b2.buffer, b1.size) != 0)

TPMI_ALG_HASH
tpm2_hash_name_to_alg(const TPMS_CAPABILITY_DATA *caps, const char *name);

const char *
tpm2_hash_alg_to_name(const TPMI_ALG_HASH alg);

TPMI_ALG_RSA_SCHEME
tpm2_num_to_alg_rsa_scheme(const int num);

TPMI_ALG_RSA_SCHEME
tpm2_rsa_scheme_name_to_alg(const char *name);

const char *
tpm2_rsa_scheme_alg_to_name(const TPMI_ALG_RSA_SCHEME alg);

TPM2_ECC_CURVE
tpm2_nid_to_ecc_curve(int nid);

int
tpm2_ecc_curve_to_nid(const TPM2_ECC_CURVE curve);

TPM2_ECC_CURVE
tpm2_name_to_ecc_curve(const char* name);

size_t
tpm2_ecc_point_to_uncompressed(const TPM2B_ECC_PARAMETER *x,
                               const TPM2B_ECC_PARAMETER *y, void **buffer);

int
tpm2_buffer_to_ecc_point(int curve_nid, const unsigned char *buf, size_t len, TPMS_ECC_POINT *point);

int
tpm2_ecdsa_size(int curve_nid);

int
tpm2_param_get_DIGEST(const OSSL_PARAM *p, TPM2B_DIGEST *digest);

#define tpm2_param_set_BN_from_buffer(p, b) tpm2_param_set_BN_from_buffer_size(p, b.buffer, b.size)
int
tpm2_param_set_BN_from_buffer_size(OSSL_PARAM *p, const BYTE *buffer, UINT16 size);

int
tpm2_param_set_BN_from_uint32(OSSL_PARAM *p, UINT32 num);

void *
revmemcpy(void *dest, const void *src, size_t len);

#endif /* TPM2_PROVIDER_TYPES_H */

