/*
 * GHASH using ARM NEON PMULL (Polynomial Multiply Long)
 *
 * Hardware-accelerated GF(2^128) multiplication for GHASH.
 * Requires ARMv8 with crypto extensions.
 *
 * Uses Karatsuba algorithm for 128-bit multiplication and
 * mbedTLS-style PMULL reduction.
 */

#ifndef CHIAKI_GHASH_PMULL_H
#define CHIAKI_GHASH_PMULL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GMAC_BLOCK_SIZE 16

/**
 * PMULL-based GHASH context
 * Stores the hash key H for multiplication
 */
typedef struct {
    uint8_t h[GMAC_BLOCK_SIZE];  /* Hash key H */
} GHashPmullCtx;

/**
 * Initialize PMULL GHASH context with hash key
 *
 * @param ctx  Context to initialize
 * @param H    16-byte hash key
 */
void ghash_pmull_init(GHashPmullCtx *ctx, const uint8_t H[GMAC_BLOCK_SIZE]);

/**
 * GF(2^128) multiplication using PMULL
 *
 * @param result  Output: 16-byte result
 * @param X       Input: 16-byte operand
 * @param H       Input: 16-byte hash key
 */
void gf128_mul_pmull(uint8_t result[GMAC_BLOCK_SIZE],
                     const uint8_t X[GMAC_BLOCK_SIZE],
                     const uint8_t H[GMAC_BLOCK_SIZE]);

/**
 * GHASH function using PMULL
 *
 * GHASH(H, data) computes:
 *   X_0 = 0
 *   X_i = (X_{i-1} ^ data_i) * H
 *   return X_m
 *
 * @param ctx       GHASH context with hash key
 * @param data      Input data
 * @param data_len  Data length in bytes
 * @param result    Output: 16-byte GHASH result (updated in place)
 */
void ghash_pmull(const GHashPmullCtx *ctx,
                 const uint8_t *data,
                 size_t data_len,
                 uint8_t result[GMAC_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CHIAKI_GHASH_PMULL_H */
