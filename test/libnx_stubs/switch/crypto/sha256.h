// libnx stub: switch/crypto/sha256.h
// OpenSSL-based implementation for desktop testing

#ifndef LIBNX_STUB_SHA256_H
#define LIBNX_STUB_SHA256_H

#include <stddef.h>

void sha256CalculateHash(void *dst, const void *src, size_t size);

#endif // LIBNX_STUB_SHA256_H
