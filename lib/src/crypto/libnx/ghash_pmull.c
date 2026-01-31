/*
 * GHASH using ARM NEON PMULL (Polynomial Multiply Long)
 *
 * Hardware-accelerated GF(2^128) multiplication for GHASH.
 * Uses Karatsuba algorithm and mbedTLS-style PMULL reduction.
 *
 * Reference: mbedTLS aesce.c (Apache 2.0)
 *
 * This file is only compiled when CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL is set.
 * Requires ARMv8 with crypto extensions.
 */

#include "ghash_pmull.h"
#include <string.h>
#include <arm_neon.h>

/*
 * GCM uses reflected bit order within each byte.
 * vrbitq_u8 reverses bits within each byte.
 */
static inline uint8x16_t gcm_reflect(uint8x16_t x)
{
    return vrbitq_u8(x);
}

/*
 * PMULL wrappers for polynomial multiply
 * pmull_low: multiply low 64 bits
 * pmull_high: multiply high 64 bits
 */
static inline poly128_t pmull_low(uint8x16_t a, uint8x16_t b)
{
    return vmull_p64(
        vgetq_lane_p64(vreinterpretq_p64_u8(a), 0),
        vgetq_lane_p64(vreinterpretq_p64_u8(b), 0)
    );
}

static inline poly128_t pmull_high(uint8x16_t a, uint8x16_t b)
{
    return vmull_high_p64(
        vreinterpretq_p64_u8(a),
        vreinterpretq_p64_u8(b)
    );
}

/*
 * Karatsuba multiplication for 128-bit polynomials
 *
 * To multiply A*B where A = Ah:Al and B = Bh:Bl:
 *   P0 = Al * Bl         (low)
 *   P1 = Ah * Bh         (high)
 *   P2 = (Al^Ah) * (Bl^Bh) = P0 ^ P1 ^ middle
 *   middle = P2 ^ P0 ^ P1
 *
 * Result is 256 bits stored as {high, middle, low}
 */
static inline uint8x16x3_t poly_mult_128(uint8x16_t a, uint8x16_t b)
{
    uint8x16x3_t result;

    /* P0 = low * low */
    poly128_t p0 = pmull_low(a, b);

    /* P1 = high * high */
    poly128_t p1 = pmull_high(a, b);

    /* For Karatsuba middle term: (Al^Ah) * (Bl^Bh) */
    uint8x16_t a_xor = veorq_u8(a, vextq_u8(a, a, 8));
    uint8x16_t b_xor = veorq_u8(b, vextq_u8(b, b, 8));
    poly128_t p2 = pmull_low(a_xor, b_xor);

    /* middle = P2 ^ P0 ^ P1 */
    uint64x2_t m = veorq_u64(
        veorq_u64(vreinterpretq_u64_p128(p2), vreinterpretq_u64_p128(p0)),
        vreinterpretq_u64_p128(p1)
    );

    result.val[0] = vreinterpretq_u8_p128(p1);  /* high 128 bits */
    result.val[1] = vreinterpretq_u8_u64(m);    /* middle 128 bits */
    result.val[2] = vreinterpretq_u8_p128(p0);  /* low 128 bits */

    return result;
}

/*
 * Reduce 256-bit polynomial modulo GCM polynomial using PMULL
 *
 * GCM polynomial: x^128 + x^7 + x^2 + x + 1
 * In reflected form: 0x87 in low byte
 *
 * Uses mbedTLS-style reduction with PMULL for the modular reduction.
 */
static inline uint8x16_t poly_mult_reduce(uint8x16x3_t input)
{
    const uint8x16_t ZERO = vdupq_n_u8(0);

    /* Reduction constant: 0x87 shifted appropriately */
    const uint8x16_t MODULO = vreinterpretq_u8_u64(
        vshrq_n_u64(vreinterpretq_u64_u8(vdupq_n_u8(0x87)), 64 - 8)
    );

    uint8x16_t h, m, l;
    uint8x16_t c, d, e, f, g, n, o;

    h = input.val[0];  /* high */
    m = input.val[1];  /* middle */
    l = input.val[2];  /* low */

    /* Reduce high part */
    c = vreinterpretq_u8_p128(pmull_high(h, MODULO));
    d = vreinterpretq_u8_p128(pmull_low(h, MODULO));

    e = veorq_u8(c, m);

    /* Reduce middle part */
    f = vreinterpretq_u8_p128(pmull_high(e, MODULO));
    g = vextq_u8(ZERO, e, 8);

    n = veorq_u8(d, l);
    o = veorq_u8(n, f);

    return veorq_u8(o, g);
}

/*
 * Full GF(2^128) multiplication with reduction
 */
void gf128_mul_pmull(uint8_t result[GMAC_BLOCK_SIZE],
                     const uint8_t X[GMAC_BLOCK_SIZE],
                     const uint8_t H[GMAC_BLOCK_SIZE])
{
    /* Load and reflect for GCM bit ordering */
    uint8x16_t x = gcm_reflect(vld1q_u8(X));
    uint8x16_t h = gcm_reflect(vld1q_u8(H));

    /* Multiply */
    uint8x16x3_t prod = poly_mult_128(x, h);

    /* Reduce */
    uint8x16_t r = poly_mult_reduce(prod);

    /* Reflect back and store */
    vst1q_u8(result, gcm_reflect(r));
}

void ghash_pmull_init(GHashPmullCtx *ctx, const uint8_t H[GMAC_BLOCK_SIZE])
{
    memcpy(ctx->h, H, GMAC_BLOCK_SIZE);
}

/*
 * XOR two 16-byte blocks
 */
static inline void xor_block(uint8_t *dst, const uint8_t *src)
{
    uint64_t *d = (uint64_t *)dst;
    const uint64_t *s = (const uint64_t *)src;
    d[0] ^= s[0];
    d[1] ^= s[1];
}

void ghash_pmull(const GHashPmullCtx *ctx,
                 const uint8_t *data,
                 size_t data_len,
                 uint8_t result[GMAC_BLOCK_SIZE])
{
    uint8_t block[GMAC_BLOCK_SIZE];

    /* Process full blocks */
    while (data_len >= GMAC_BLOCK_SIZE) {
        xor_block(result, data);
        gf128_mul_pmull(result, result, ctx->h);
        data += GMAC_BLOCK_SIZE;
        data_len -= GMAC_BLOCK_SIZE;
    }

    /* Process remaining partial block (zero-padded) */
    if (data_len > 0) {
        memset(block, 0, GMAC_BLOCK_SIZE);
        memcpy(block, data, data_len);
        xor_block(result, block);
        gf128_mul_pmull(result, result, ctx->h);
    }
}
