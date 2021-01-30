/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_ALGORITHMS_H
#define TPM2_PROVIDER_ALGORITHMS_H

#include <tss2_tpm2_types.h>

TPMI_ALG_HASH
tpm2_name_to_alg_hash(const char *name);

TPMI_ALG_RSA_SCHEME
tpm2_name_to_alg_rsa_scheme(const char *name);

int
tpm2_sig_scheme_to_x509_alg(const TPMT_SIG_SCHEME *scheme, TPM2_ALG_ID digalg,
                            unsigned char **aid, int *aid_size);

#endif /* TPM2_PROVIDER_ALGORITHMS_H */

