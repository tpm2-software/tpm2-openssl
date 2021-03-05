/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_ALGORITHMS_H
#define TPM2_PROVIDER_ALGORITHMS_H

#include <tss2/tss2_tpm2_types.h>

TPMI_ALG_HASH
tpm2_hash_name_to_alg(const char *name);

const char *
tpm2_hash_alg_to_name(const TPMI_ALG_HASH alg);

TPMI_ALG_RSA_SCHEME
tpm2_num_to_alg_rsa_scheme(const int num);

TPMI_ALG_RSA_SCHEME
tpm2_rsa_scheme_name_to_alg(const char *name);

const char *
tpm2_rsa_scheme_alg_to_name(const TPMI_ALG_RSA_SCHEME alg);

ASN1_STRING *
tpm2_get_rsapss_params(int key_bits, TPM2_ALG_ID digalg);

int
tpm2_sig_scheme_to_x509_alg(int key_bits, const TPMT_SIG_SCHEME *scheme,
                            unsigned char **aid, int *aid_size);

#endif /* TPM2_PROVIDER_ALGORITHMS_H */

