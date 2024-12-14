/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_SEMAPHORE_H
#define TPM2_PROVIDER_SEMAPHORE_H

#if defined(_WIN32) || defined(_WIN64)

#include <windows.h>
typedef HANDLE tpm2_semaphore_t;

#else

#include <semaphore.h>
typedef sem_t* tpm2_semaphore_t;

#endif

tpm2_semaphore_t tpm2_semaphore_new();

/* returns 1 on success, 0 on error */
int tpm2_semaphore_lock(tpm2_semaphore_t sem);

/* returns 1 on success, 0 on error */
int tpm2_semaphore_unlock(tpm2_semaphore_t sem);

void tpm2_semaphore_free(tpm2_semaphore_t sem);

#endif /* TPM2_PROVIDER_SEMAPHORE_H */

