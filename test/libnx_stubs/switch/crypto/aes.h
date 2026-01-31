// libnx stub: switch/crypto/aes.h
// OpenSSL-based implementation for desktop testing

#ifndef LIBNX_STUB_AES_H
#define LIBNX_STUB_AES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define AES_BLOCK_SIZE      0x10
#define AES_128_KEY_SIZE    0x10
#define AES_128_NUM_ROUNDS  10

// Match libnx struct layout (176 bytes)
// We only use the first 16 bytes to store the key for our OpenSSL impl
typedef struct {
    uint8_t round_keys[AES_128_NUM_ROUNDS+1][AES_BLOCK_SIZE];
} Aes128Context;

void aes128ContextCreate(Aes128Context *out, const void *key, bool is_encryptor);
void aes128EncryptBlock(const Aes128Context *ctx, void *dst, const void *src);

#endif // LIBNX_STUB_AES_H
