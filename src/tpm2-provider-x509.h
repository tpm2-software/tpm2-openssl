/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_RSA_X509_H
#define TPM2_PROVIDER_RSA_X509_H

#include <openssl/x509.h>

#include <tss2/tss2_tpm2_types.h>

ASN1_STRING *
tpm2_get_x509_rsapss_params(int key_bits, TPM2_ALG_ID digalg);

int
tpm2_sig_scheme_to_x509_alg(const TPMT_SIG_SCHEME *scheme, const TPMU_PUBLIC_PARMS *params,
                            unsigned char **aid, int *aid_size);

#endif /* TPM2_PROVIDER_RSA_X509_H */

