/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/provider.h>

int main() {
    OSSL_PROVIDER *prov;
    int res;

    if ((prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
        return 2;

    /* returns 0 or 1 */
    res = !OSSL_PROVIDER_self_test(prov);

    if (!OSSL_PROVIDER_unload(prov))
        return 3;

    return res;
}

