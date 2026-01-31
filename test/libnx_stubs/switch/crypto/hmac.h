// libnx stub: switch/crypto/hmac.h
// OpenSSL-based implementation for desktop testing

#ifndef LIBNX_STUB_HMAC_H
#define LIBNX_STUB_HMAC_H

#include <stddef.h>

void hmacSha256CalculateMac(void *dst, const void *key, size_t key_size,
                            const void *src, size_t size);

#endif // LIBNX_STUB_HMAC_H
