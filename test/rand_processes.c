/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/provider.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/wait.h>

#define PROCESS_COUNT 10

int generate_random() {
    unsigned char buffer[1024];

    /* 1 on success */
    return (RAND_bytes(buffer, sizeof(buffer)) == 1);
}

int main() {
    OSSL_PROVIDER *prov;
    pid_t process[PROCESS_COUNT];
    int i, failed = 0;
    int res;

    if ((prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
        return PROCESS_COUNT+1;

    /* start multiple parallel operations */
    for (i = 0; i < PROCESS_COUNT; i++) {
        process[i] = fork();
        if (process[i] < 0) {
            /* failure */
            return PROCESS_COUNT+2;
        } else if (process[i] == 0) {
            /* child process */
            return generate_random();
        }
    }

    /* count failures */
    for (i = 0; i < PROCESS_COUNT; i++) {
        if (waitpid(process[i], &res, 0) != process[i] || !res)
            failed++;
    }

    if (!OSSL_PROVIDER_unload(prov))
        return PROCESS_COUNT+3;

    return failed;
}

