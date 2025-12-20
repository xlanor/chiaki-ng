// libnx stub: switch/services/csrng.h
// OpenSSL-based implementation for desktop testing

#ifndef LIBNX_STUB_CSRNG_H
#define LIBNX_STUB_CSRNG_H

#include <stdint.h>
#include <stddef.h>

typedef uint32_t Result;

#define R_FAILED(rc)    ((rc) != 0)
#define R_SUCCEEDED(rc) ((rc) == 0)

Result csrngInitialize(void);
Result csrngGetRandomBytes(void *out, size_t out_size);
void csrngExit(void);

#endif // LIBNX_STUB_CSRNG_H
