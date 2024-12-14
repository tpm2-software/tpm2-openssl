/* SPDX-License-Identifier: BSD-3-Clause */

#include "tpm2-provider-semaphore.h"

#if defined(_WIN32) || defined(_WIN64)

tpm2_semaphore_t tpm2_semaphore_new()
{
    return CreateSemaphore(NULL, 1, 1, NULL);
}

/* returns 1 on success, 0 on error */
int tpm2_semaphore_lock(tpm2_semaphore_t sem)
{
    return (WaitForSingleObject(sem, INFINITE) == 0);
}

/* returns 1 on success, 0 on error */
int tpm2_semaphore_unlock(tpm2_semaphore_t sem)
{
    return (ReleaseSemaphore(sem, 1, NULL) != 0);
}

void tpm2_semaphore_free(tpm2_semaphore_t sem)
{
    CloseHandle(sem);
}

#else

#include <stddef.h>
#include <errno.h>
#include <sys/mman.h>

tpm2_semaphore_t tpm2_semaphore_new()
{
    tpm2_semaphore_t sem;

    sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sem == MAP_FAILED) {
        return NULL;
    }

    if (sem_init(sem, 1, 1) == -1) {
        munmap(sem, sizeof(sem_t));
        return NULL;
    }
    return sem;
}

/* returns 1 on success, 0 on error */
int tpm2_semaphore_lock(tpm2_semaphore_t sem)
{
    int rc;

    do {
        rc = sem_wait(sem);
    } while (rc == -1 && errno == EINTR);

    return (rc == 0);
}

/* returns 1 on success, 0 on error */
int tpm2_semaphore_unlock(tpm2_semaphore_t sem)
{
    return (sem_post(sem) == 0);
}

void tpm2_semaphore_free(tpm2_semaphore_t sem)
{
    sem_close(sem);
    munmap(sem, sizeof(sem_t));
}

#endif

