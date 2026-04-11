/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#include "tpm2-provider-ctx.h"

/* the file format is defined in tpm2-tools/lib/files.c */
static const uint32_t MAGIC = 0xBADCC0DE;
#define CONTEXT_VERSION 1

// magic(4) + version(4) + hierarchy(4) + savedHandle(4) + sequence(8) + contextBlob.size(2)
#define CTX_HEADER_SIZE 26

int
tpm2_read_context_raw(BIO *bin, unsigned char **out_data, size_t *out_size)
{
    unsigned char header[CTX_HEADER_SIZE];
    uint32_t magic, version;
    uint16_t blob_size;

    if (BIO_read(bin, header, CTX_HEADER_SIZE) != CTX_HEADER_SIZE)
        return 0;

    memcpy(&magic, header, 4);
    if (be32toh(magic) != MAGIC)
        return 0;

    memcpy(&version, header + 4, 4);
    if (be32toh(version) != CONTEXT_VERSION)
        return 0;

    memcpy(&blob_size, header + 24, 2);
    blob_size = be16toh(blob_size);
    if (blob_size > sizeof(TPM2B_CONTEXT_DATA))
        return 0;

    *out_size = CTX_HEADER_SIZE + blob_size;
    *out_data = OPENSSL_malloc(*out_size);
    if (*out_data == NULL)
        return 0;

    memcpy(*out_data, header, CTX_HEADER_SIZE);

    if (BIO_read(bin, *out_data + CTX_HEADER_SIZE, blob_size) != (int)blob_size) {
        OPENSSL_free(*out_data);
        *out_data = NULL;
        return 0;
    }

    return 1;
}

#define DEFINE_BIO_READ(size) \
    static int \
    BIO_read_uint##size(BIO *b, uint##size##_t *val) \
    { \
        uint##size##_t v; \
        if (BIO_read(b, &v, sizeof(uint##size##_t)) == sizeof(uint##size##_t)) { \
            *val = be##size##toh(v); \
            return 1; \
        } \
        return 0; \
    }

DEFINE_BIO_READ(16)
DEFINE_BIO_READ(32)
DEFINE_BIO_READ(64)

int
tpm2_read_context(BIO *bin, TPMS_CONTEXT *context)
{
    uint32_t magic, version;

    if (!BIO_read_uint32(bin, &magic) || magic != MAGIC
            || !BIO_read_uint32(bin, &version) || version != CONTEXT_VERSION
            || !BIO_read_uint32(bin, &context->hierarchy)
            || !BIO_read_uint32(bin, &context->savedHandle)
            || !BIO_read_uint64(bin, &context->sequence)
            || !BIO_read_uint16(bin, &context->contextBlob.size)
            || context->contextBlob.size > sizeof(context->contextBlob.buffer)
            || BIO_read(bin, context->contextBlob.buffer, context->contextBlob.size)
                != context->contextBlob.size) {
        /* this is not our file */
        return 0;
    }

    return 1;
}
