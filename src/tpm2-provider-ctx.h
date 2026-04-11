/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_CTX_H
#define TPM2_PROVIDER_CTX_H

#include "tpm2-provider.h"

int
tpm2_read_context_raw(BIO *bin, unsigned char **out_data, size_t *out_size);

int
tpm2_read_context(BIO *bin, TPMS_CONTEXT *context);

#endif /* TPM2_PROVIDER_CTX_H */
