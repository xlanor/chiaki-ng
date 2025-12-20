/*
 * AES-CFB128 implementation for chiaki-ng libnx crypto backend
 *
 * Implements AES-CFB128 mode using libnx's hardware-accelerated AES-ECB.
 * Used for PlayStation Remote Play authentication protocol.
 */

#ifndef CHIAKI_AES_CFB_H
#define CHIAKI_AES_CFB_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16

/**
 * AES-128-CFB128 encryption/decryption
 *
 * @param key       16-byte AES key
 * @param iv        16-byte IV (will be modified in-place for chaining)
 * @param iv_off    Offset within current IV block (for streaming, usually 0)
 * @param input     Input data
 * @param output    Output data (can be same as input for in-place operation)
 * @param length    Data length in bytes
 * @param encrypt   1 for encryption, 0 for decryption
 * @return 0 on success, non-zero on error
 */
int chiaki_aes_cfb128_crypt(
    const uint8_t key[16],
    uint8_t iv[16],
    size_t *iv_off,
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    int encrypt
);

#endif /* CHIAKI_AES_CFB_H */
