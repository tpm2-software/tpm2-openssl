/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/provider.h>
#include <openssl/rand.h>

#define THREAD_COUNT 10

void *generate_random(void *arg) {
    unsigned char buffer[1024];

    /* 1 on success */
    return (void *)(size_t)(RAND_bytes(buffer, sizeof(buffer)) == 1);
}

int main() {
    OSSL_PROVIDER *prov;
    pthread_t thread[THREAD_COUNT];
    int i, failed = 0;
    size_t res;

    if ((prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
        return THREAD_COUNT+1;

    /* start multiple parallel operations */
    for (i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(thread+i, NULL, generate_random, NULL))
            return THREAD_COUNT+2;
    }

    /* count failures */
    for (i = 0; i < THREAD_COUNT; i++) {
        if (pthread_join(thread[i], (void **)&res) || !res)
            failed++;
    }

    if (!OSSL_PROVIDER_unload(prov))
        return THREAD_COUNT+3;

    return failed;
}

