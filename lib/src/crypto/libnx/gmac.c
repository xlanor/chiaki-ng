/*
 * GMAC (Galois Message Authentication Code) for chiaki-ng libnx crypto backend
 *
 * Implements GMAC using libnx's hardware-accelerated AES-ECB for the
 * underlying block cipher, with software GHASH for the Galois field operations.
 *
 * GF(2^128) multiplication uses the irreducible polynomial:
 * P(x) = x^128 + x^7 + x^2 + x + 1
 */

#include "gmac.h"
#include <string.h>

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
#include <switch/crypto/aes.h>
#endif

/* Reduction polynomial: x^128 + x^7 + x^2 + x + 1 */
/* When the high bit overflows, we XOR with 0x87 (the low bits of the polynomial) */
#define GF128_RB 0x87

/**
 * XOR two 16-byte blocks: dst ^= src
 */
static void xor_block(uint8_t *dst, const uint8_t *src)
{
    for (int i = 0; i < GMAC_BLOCK_SIZE; i++) {
        dst[i] ^= src[i];
    }
}

/**
 * Multiply by 2 in GF(2^128) - shift left by 1 with reduction
 * This operates on big-endian representation
 */
static void gf128_mul2(uint8_t *block)
{
    uint8_t carry = 0;

    /* Shift left by 1 bit, from LSB to MSB (big-endian) */
    for (int i = GMAC_BLOCK_SIZE - 1; i >= 0; i--) {
        uint8_t new_carry = (block[i] >> 7) & 1;
        block[i] = (block[i] << 1) | carry;
        carry = new_carry;
    }

    /* If there was overflow, reduce by XORing with R (0x87 at the end) */
    if (carry) {
        block[GMAC_BLOCK_SIZE - 1] ^= GF128_RB;
    }
}

/**
 * GF(2^128) multiplication: result = X * Y
 * Uses simple bit-by-bit method (not fastest, but simple and correct)
 */
static void gf128_mul(uint8_t *result, const uint8_t *X, const uint8_t *Y)
{
    uint8_t V[GMAC_BLOCK_SIZE];
    uint8_t Z[GMAC_BLOCK_SIZE];

    memcpy(V, Y, GMAC_BLOCK_SIZE);
    memset(Z, 0, GMAC_BLOCK_SIZE);

    /* Process each bit of X from MSB to LSB */
    for (int i = 0; i < GMAC_BLOCK_SIZE; i++) {
        for (int j = 7; j >= 0; j--) {
            /* If bit is set, Z ^= V */
            if ((X[i] >> j) & 1) {
                xor_block(Z, V);
            }

            /* V = V * x (multiply by 2 in the field) */
            /* Check if we need to reduce before shifting */
            uint8_t lsb = V[GMAC_BLOCK_SIZE - 1] & 1;

            /* Shift right by 1 (this is actually multiply by x in GCM's convention) */
            for (int k = GMAC_BLOCK_SIZE - 1; k > 0; k--) {
                V[k] = (V[k] >> 1) | ((V[k-1] & 1) << 7);
            }
            V[0] >>= 1;

            /* If LSB was set, XOR with reduction polynomial */
            if (lsb) {
                V[0] ^= 0xe1;  /* Reduction in GCM's bit ordering */
            }
        }
    }

    memcpy(result, Z, GMAC_BLOCK_SIZE);
}

/**
 * GHASH function: compute GHASH over data with given H
 *
 * GHASH(H, A) = X_m where:
 *   X_0 = 0
 *   X_i = (X_{i-1} ^ A_i) * H
 */
static void ghash(
    const uint8_t H[GMAC_BLOCK_SIZE],
    const uint8_t *data,
    size_t data_len,
    uint8_t result[GMAC_BLOCK_SIZE])
{
    uint8_t block[GMAC_BLOCK_SIZE];

    /* Process full blocks */
    while (data_len >= GMAC_BLOCK_SIZE) {
        xor_block(result, data);
        gf128_mul(result, result, H);
        data += GMAC_BLOCK_SIZE;
        data_len -= GMAC_BLOCK_SIZE;
    }

    /* Process remaining partial block (zero-padded) */
    if (data_len > 0) {
        memset(block, 0, GMAC_BLOCK_SIZE);
        memcpy(block, data, data_len);
        xor_block(result, block);
        gf128_mul(result, result, H);
    }
}

/**
 * Increment counter block (for J0 -> J1)
 */
static void inc32(uint8_t block[GMAC_BLOCK_SIZE])
{
    /* Increment the last 32 bits as big-endian counter */
    for (int i = GMAC_BLOCK_SIZE - 1; i >= GMAC_BLOCK_SIZE - 4; i--) {
        if (++block[i] != 0) {
            break;
        }
    }
}

int chiaki_gmac_compute(
    const uint8_t key[16],
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *tag,
    size_t tag_len)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
    Aes128Context ctx;
    uint8_t H[GMAC_BLOCK_SIZE];
    uint8_t Y[GMAC_BLOCK_SIZE];
    uint8_t J0[GMAC_BLOCK_SIZE];
    uint8_t len_block[GMAC_BLOCK_SIZE];
    uint8_t S[GMAC_BLOCK_SIZE];

    if (tag_len > GMAC_TAG_SIZE) {
        tag_len = GMAC_TAG_SIZE;
    }

    /* Create AES context */
    aes128ContextCreate(&ctx, key, true);

    /* Compute H = AES_K(0^128) - the hash key */
    memset(H, 0, GMAC_BLOCK_SIZE);
    aes128EncryptBlock(&ctx, H, H);

    /* Compute J0 (initial counter block) */
    if (iv_len == 12) {
        /* If IV is 96 bits, J0 = IV || 0^31 || 1 */
        memset(J0, 0, GMAC_BLOCK_SIZE);
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        /* Otherwise, J0 = GHASH_H(IV || 0^s || len(IV)) */
        /* For simplicity with 16-byte IV used by chiaki: */
        memset(J0, 0, GMAC_BLOCK_SIZE);
        ghash(H, iv, iv_len, J0);

        /* Add length block */
        memset(len_block, 0, GMAC_BLOCK_SIZE);
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        len_block[8]  = (iv_bits >> 56) & 0xff;
        len_block[9]  = (iv_bits >> 48) & 0xff;
        len_block[10] = (iv_bits >> 40) & 0xff;
        len_block[11] = (iv_bits >> 32) & 0xff;
        len_block[12] = (iv_bits >> 24) & 0xff;
        len_block[13] = (iv_bits >> 16) & 0xff;
        len_block[14] = (iv_bits >> 8) & 0xff;
        len_block[15] = iv_bits & 0xff;

        xor_block(J0, len_block);
        gf128_mul(J0, J0, H);
    }

    /* Initialize GHASH state Y = 0 */
    memset(Y, 0, GMAC_BLOCK_SIZE);

    /* Process AAD through GHASH */
    ghash(H, aad, aad_len, Y);

    /* For GMAC (no ciphertext), we skip the ciphertext GHASH step */

    /* Create length block: len(A) || len(C) in bits, both as 64-bit big-endian */
    memset(len_block, 0, GMAC_BLOCK_SIZE);
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    /* AAD length in first 64 bits */
    len_block[0] = (aad_bits >> 56) & 0xff;
    len_block[1] = (aad_bits >> 48) & 0xff;
    len_block[2] = (aad_bits >> 40) & 0xff;
    len_block[3] = (aad_bits >> 32) & 0xff;
    len_block[4] = (aad_bits >> 24) & 0xff;
    len_block[5] = (aad_bits >> 16) & 0xff;
    len_block[6] = (aad_bits >> 8) & 0xff;
    len_block[7] = aad_bits & 0xff;
    /* Ciphertext length = 0 for GMAC (bytes 8-15 stay 0) */

    /* Final GHASH step with length block */
    xor_block(Y, len_block);
    gf128_mul(Y, Y, H);

    /* S = GHASH(H, A || 0^v || C || 0^u || len(A) || len(C)) - this is Y now */
    /* Tag = S XOR AES_K(J0) */
    aes128EncryptBlock(&ctx, S, J0);
    xor_block(S, Y);

    memcpy(tag, S, tag_len);

    return 0;
#else
    (void)key;
    (void)iv;
    (void)iv_len;
    (void)aad;
    (void)aad_len;
    (void)tag;
    (void)tag_len;
    return -1;
#endif
}
