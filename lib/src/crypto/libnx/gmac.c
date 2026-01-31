/*
 * GMAC (Galois Message Authentication Code) for chiaki-ng libnx crypto backend
 *
 * Implements GMAC using libnx's hardware-accelerated AES-ECB for the
 * underlying block cipher, with 8-bit table-driven GHASH for fast
 * Galois field operations.
 *
 * GF(2^128) multiplication uses the irreducible polynomial:
 * P(x) = x^128 + x^7 + x^2 + x + 1
 *
 * The 8-bit table method processes 8 bits at a time instead of 1 bit,
 * providing ~8x speedup over the naive bit-by-bit approach.
 */

#include "gmac.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL
#include "ghash_pmull.h"
#endif

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
#include <switch/crypto/aes.h>
#endif

static ChiakiLibnxGhashMode g_ghash_mode = CHIAKI_LIBNX_GHASH_TABLE;

#if defined(__SWITCH__) || defined(CHIAKI_LIB_ENABLE_LIBNX_CRYPTO)
void chiaki_libnx_set_ghash_mode(ChiakiLibnxGhashMode mode)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL
    g_ghash_mode = mode;
#else
    if (mode == CHIAKI_LIBNX_GHASH_PMULL) {
        fprintf(stderr, "WARNING: PMULL mode requested but not compiled in "
                "(CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL not set), using TABLE mode\n");
        g_ghash_mode = CHIAKI_LIBNX_GHASH_TABLE;
    } else {
        g_ghash_mode = mode;
    }
#endif
}

ChiakiLibnxGhashMode chiaki_libnx_get_ghash_mode(void)
{
    return g_ghash_mode;
}
#endif

/*
 * Precomputed reduction table for x^8 shift in GF(2^128) with GCM bit ordering.
 * R[b] = reduction value for overflow byte b when shifting right by 8 bits.
 * This is constant - it only depends on the GCM reduction polynomial:
 * P(x) = x^128 + x^7 + x^2 + x + 1
 *
 * Generated from the formula in the original ghash_table_init():
 *   r0 = (b7<<7) | ((b7^b6)<<6) | ((b7^b6^b5)<<5) | ((b6^b5^b4)<<4) |
 *        ((b5^b4^b3)<<3) | ((b4^b3^b2)<<2) | ((b3^b2^b1)<<1) | (b7^b2^b1^b0)
 *   r1 = ((b6^b1^b0)<<7) | ((b5^b0)<<6) | (b4<<5) | (b3<<4) |
 *        (b2<<3) | (b1<<2) | (b0<<1)
 *   R[b] = (r0 << 8) | r1
 */
static const uint16_t GHASH_REDUCTION_TABLE[256] = {
    /* 0x00-0x0f */ 0x0000, 0x01c2, 0x0384, 0x0246, 0x0708, 0x06ca, 0x048c, 0x054e,
                    0x0e10, 0x0fd2, 0x0d94, 0x0c56, 0x0918, 0x08da, 0x0a9c, 0x0b5e,
    /* 0x10-0x1f */ 0x1c20, 0x1de2, 0x1fa4, 0x1e66, 0x1b28, 0x1aea, 0x18ac, 0x196e,
                    0x1230, 0x13f2, 0x11b4, 0x1076, 0x1538, 0x14fa, 0x16bc, 0x177e,
    /* 0x20-0x2f */ 0x3840, 0x3982, 0x3bc4, 0x3a06, 0x3f48, 0x3e8a, 0x3ccc, 0x3d0e,
                    0x3650, 0x3792, 0x35d4, 0x3416, 0x3158, 0x309a, 0x32dc, 0x331e,
    /* 0x30-0x3f */ 0x2460, 0x25a2, 0x27e4, 0x2626, 0x2368, 0x22aa, 0x20ec, 0x212e,
                    0x2a70, 0x2bb2, 0x29f4, 0x2836, 0x2d78, 0x2cba, 0x2efc, 0x2f3e,
    /* 0x40-0x4f */ 0x7080, 0x7142, 0x7304, 0x72c6, 0x7788, 0x764a, 0x740c, 0x75ce,
                    0x7e90, 0x7f52, 0x7d14, 0x7cd6, 0x7998, 0x785a, 0x7a1c, 0x7bde,
    /* 0x50-0x5f */ 0x6ca0, 0x6d62, 0x6f24, 0x6ee6, 0x6ba8, 0x6a6a, 0x682c, 0x69ee,
                    0x62b0, 0x6372, 0x6134, 0x60f6, 0x65b8, 0x647a, 0x663c, 0x67fe,
    /* 0x60-0x6f */ 0x48c0, 0x4902, 0x4b44, 0x4a86, 0x4fc8, 0x4e0a, 0x4c4c, 0x4d8e,
                    0x46d0, 0x4712, 0x4554, 0x4496, 0x41d8, 0x401a, 0x425c, 0x439e,
    /* 0x70-0x7f */ 0x54e0, 0x5522, 0x5764, 0x56a6, 0x53e8, 0x522a, 0x506c, 0x51ae,
                    0x5af0, 0x5b32, 0x5974, 0x58b6, 0x5df8, 0x5c3a, 0x5e7c, 0x5fbe,
    /* 0x80-0x8f */ 0xe100, 0xe0c2, 0xe284, 0xe346, 0xe608, 0xe7ca, 0xe58c, 0xe44e,
                    0xef10, 0xeed2, 0xec94, 0xed56, 0xe818, 0xe9da, 0xeb9c, 0xea5e,
    /* 0x90-0x9f */ 0xfd20, 0xfce2, 0xfea4, 0xff66, 0xfa28, 0xfbea, 0xf9ac, 0xf86e,
                    0xf330, 0xf2f2, 0xf0b4, 0xf176, 0xf438, 0xf5fa, 0xf7bc, 0xf67e,
    /* 0xa0-0xaf */ 0xd940, 0xd882, 0xdac4, 0xdb06, 0xde48, 0xdf8a, 0xddcc, 0xdc0e,
                    0xd750, 0xd692, 0xd4d4, 0xd516, 0xd058, 0xd19a, 0xd3dc, 0xd21e,
    /* 0xb0-0xbf */ 0xc560, 0xc4a2, 0xc6e4, 0xc726, 0xc268, 0xc3aa, 0xc1ec, 0xc02e,
                    0xcb70, 0xcab2, 0xc8f4, 0xc936, 0xcc78, 0xcdba, 0xcffc, 0xce3e,
    /* 0xc0-0xcf */ 0x9180, 0x9042, 0x9204, 0x93c6, 0x9688, 0x974a, 0x950c, 0x94ce,
                    0x9f90, 0x9e52, 0x9c14, 0x9dd6, 0x9898, 0x995a, 0x9b1c, 0x9ade,
    /* 0xd0-0xdf */ 0x8da0, 0x8c62, 0x8e24, 0x8fe6, 0x8aa8, 0x8b6a, 0x892c, 0x88ee,
                    0x83b0, 0x8272, 0x8034, 0x81f6, 0x84b8, 0x857a, 0x873c, 0x86fe,
    /* 0xe0-0xef */ 0xa9c0, 0xa802, 0xaa44, 0xab86, 0xaec8, 0xaf0a, 0xad4c, 0xac8e,
                    0xa7d0, 0xa612, 0xa454, 0xa596, 0xa0d8, 0xa11a, 0xa35c, 0xa29e,
    /* 0xf0-0xff */ 0xb5e0, 0xb422, 0xb664, 0xb7a6, 0xb2e8, 0xb32a, 0xb16c, 0xb0ae,
                    0xbbf0, 0xba32, 0xb874, 0xb9b6, 0xbcf8, 0xbd3a, 0xbf7c, 0xbebe
};

/*
 * Precomputed multiplication table for 8-bit GHASH multiplication.
 * M[256][16]: M[b] = b * H in GF(2^128)
 * This is key-dependent and must be computed per key.
 * Total memory: 4KB
 */
typedef struct GHashTable {
    uint8_t M[256][GMAC_BLOCK_SIZE];  /* Multiplication table: M[b] = b * H */
} GHashTable;

/**
 * XOR two 16-byte blocks: dst ^= src
 * Uses 64-bit operations for better performance
 */
static inline void xor_block(uint8_t *dst, const uint8_t *src)
{
    uint64_t *d = (uint64_t *)dst;
    const uint64_t *s = (const uint64_t *)src;
    d[0] ^= s[0];
    d[1] ^= s[1];
}

/**
 * Shift block right by 1 bit in GCM bit ordering
 * Returns the bit that was shifted out (LSB of last byte)
 */
static inline int shift_right_1(uint8_t *block)
{
    int carry = 0;
    for (int i = 0; i < GMAC_BLOCK_SIZE; i++) {
        int new_carry = block[i] & 1;
        block[i] = (block[i] >> 1) | (carry << 7);
        carry = new_carry;
    }
    return carry;
}

/**
 * Double in GF(2^128) with GCM bit ordering (multiply by x)
 * If MSB is set, reduce by XORing with the polynomial (0xe1 in high byte)
 */
static void gf128_double(uint8_t *out, const uint8_t *in)
{
    memcpy(out, in, GMAC_BLOCK_SIZE);
    int carry = shift_right_1(out);
    if (carry) {
        out[0] ^= 0xe1;  /* Reduction polynomial in GCM bit ordering */
    }
}

/**
 * Initialize GHASH multiplication table for a given hash key H
 *
 * This precomputes M[b] = b * H for all byte values b = 0..255
 * Using the property that GF multiplication is linear over XOR:
 *   M[a ^ b] = M[a] ^ M[b]
 *
 * We only need to compute M for powers of 2, then derive others via XOR.
 */
static void ghash_table_init(GHashTable *t, const uint8_t H[GMAC_BLOCK_SIZE])
{
    /* M[0] = 0 */
    memset(t->M[0], 0, GMAC_BLOCK_SIZE);

    /*
     * M[128] = H
     * In GCM's reflected bit ordering, byte value 128 (0x80) represents x^0 = 1
     * So M[128] = 1 * H = H
     */
    memcpy(t->M[128], H, GMAC_BLOCK_SIZE);

    /*
     * Compute M[64], M[32], M[16], M[8], M[4], M[2], M[1] by doubling
     * M[64] = H * x, M[32] = H * x^2, ..., M[1] = H * x^7
     */
    for (int i = 64; i >= 1; i >>= 1) {
        gf128_double(t->M[i], t->M[i * 2]);
    }

    /*
     * Fill remaining entries using XOR (linear combination)
     * For any i with multiple bits set: M[i] = M[hi] ^ M[lo]
     * where hi is the highest set bit and lo is the rest
     */
    for (int i = 2; i < 256; i++) {
        /* Skip if i is a power of 2 (already computed) */
        if ((i & (i - 1)) == 0)
            continue;

        /* Find lowest set bit */
        int lo = i & (-i);
        int hi = i ^ lo;
        memcpy(t->M[i], t->M[hi], GMAC_BLOCK_SIZE);
        xor_block(t->M[i], t->M[lo]);
    }

    /* R[256] reduction table is now static const GHASH_REDUCTION_TABLE */
}

/**
 * GF(2^128) multiply using 8-bit table lookup
 * Computes: result = X * H (using precomputed table for H)
 *
 * Algorithm:
 * 1. Start with Z = M[X[15]] (LSB of X)
 * 2. For each remaining byte from X[14] to X[0]:
 *    a. Shift Z right by 8 bits with reduction
 *    b. XOR in M[X[i]]
 */
static void gf128_mul_table(
    uint8_t result[GMAC_BLOCK_SIZE],
    const uint8_t X[GMAC_BLOCK_SIZE],
    const GHashTable *t)
{
    uint8_t Z[GMAC_BLOCK_SIZE];

    /* Start with Z = M[X[15]] */
    memcpy(Z, t->M[X[15]], GMAC_BLOCK_SIZE);

    /* Process remaining bytes from X[14] down to X[0] */
    for (int i = 14; i >= 0; i--) {
        /* Save the byte that will overflow */
        uint8_t overflow = Z[15];

        /* Shift Z right by 8 bits (one byte) */
        memmove(Z + 1, Z, 15);
        Z[0] = 0;

        /* Apply reduction for the overflow byte using static table */
        uint16_t r = GHASH_REDUCTION_TABLE[overflow];
        Z[0] ^= (r >> 8) & 0xff;
        Z[1] ^= r & 0xff;

        /* XOR in the next term from the table */
        xor_block(Z, t->M[X[i]]);
    }

    memcpy(result, Z, GMAC_BLOCK_SIZE);
}

/**
 * GHASH function using table lookup
 *
 * GHASH(H, data) computes:
 *   X_0 = 0
 *   X_i = (X_{i-1} ^ data_i) * H
 *   return X_m
 */
static void ghash_table(
    const GHashTable *t,
    const uint8_t *data,
    size_t data_len,
    uint8_t result[GMAC_BLOCK_SIZE])
{
    uint8_t block[GMAC_BLOCK_SIZE];

    /* Process full blocks */
    while (data_len >= GMAC_BLOCK_SIZE) {
        xor_block(result, data);
        gf128_mul_table(result, result, t);
        data += GMAC_BLOCK_SIZE;
        data_len -= GMAC_BLOCK_SIZE;
    }

    /* Process remaining partial block (zero-padded) */
    if (data_len > 0) {
        memset(block, 0, GMAC_BLOCK_SIZE);
        memcpy(block, data, data_len);
        xor_block(result, block);
        gf128_mul_table(result, result, t);
    }
}

/**
 * Compute GMAC authentication tag
 *
 * GMAC is GCM mode with no ciphertext (authentication only).
 * The tag is computed as:
 *   H = AES_K(0^128)
 *   J0 = IV || 0^31 || 1  (for 96-bit IV) or GHASH_H(IV || padding || len(IV))
 *   Y = GHASH_H(AAD || padding || len(AAD) || len(C))
 *   Tag = Y ^ AES_K(J0)
 */
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
    GHashTable table;

    if (tag_len > GMAC_TAG_SIZE) {
        tag_len = GMAC_TAG_SIZE;
    }

    /* Create AES context */
    aes128ContextCreate(&ctx, key, true);

    /* Compute H = AES_K(0^128) - the hash key */
    memset(H, 0, GMAC_BLOCK_SIZE);
    aes128EncryptBlock(&ctx, H, H);

    /* Initialize GHASH table for this H */
    ghash_table_init(&table, H);

    /* Compute J0 (initial counter block) */
    memset(J0, 0, GMAC_BLOCK_SIZE);
    if (iv_len == 12) {
        /* If IV is 96 bits, J0 = IV || 0^31 || 1 */
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        /* Otherwise, J0 = GHASH_H(IV || 0^s || len(IV)) */
        ghash_table(&table, iv, iv_len, J0);

        /* Add length block: 64 bits of 0 || 64 bits of IV length in bits */
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
        gf128_mul_table(J0, J0, &table);
    }

    /* Initialize GHASH state Y = 0 */
    memset(Y, 0, GMAC_BLOCK_SIZE);

    /* Process AAD through GHASH */
    ghash_table(&table, aad, aad_len, Y);

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
    gf128_mul_table(Y, Y, &table);

    /* S = Y (final GHASH output) */
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

/**
 * Initialize GMAC context for table caching
 */
void chiaki_gmac_context_init(ChiakiGmacContext *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode = g_ghash_mode;  /* Use global mode setting */
    ctx->table = NULL;
    ctx->initialized = false;
    ctx->table_init_count = 0;
}

/**
 * Free resources held by GMAC context
 */
void chiaki_gmac_context_fini(ChiakiGmacContext *ctx)
{
    if (ctx->table) {
        free(ctx->table);
        ctx->table = NULL;
    }
    ctx->initialized = false;
}

/**
 * Compute GMAC with cached context
 *
 * If the key matches the cached key, reuses precomputed tables.
 * Otherwise, recomputes tables and updates the cache.
 */
int chiaki_gmac_compute_cached(
    ChiakiGmacContext *ctx,
    const uint8_t key[16],
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *tag,
    size_t tag_len)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
    uint8_t Y[GMAC_BLOCK_SIZE];
    uint8_t J0[GMAC_BLOCK_SIZE];
    uint8_t len_block[GMAC_BLOCK_SIZE];
    uint8_t S[GMAC_BLOCK_SIZE];

    if (tag_len > GMAC_TAG_SIZE)
        tag_len = GMAC_TAG_SIZE;

    /* Check if we need to recompute tables (key changed or not initialized) */
    bool need_recompute = !ctx->initialized ||
                          memcmp(ctx->key, key, GMAC_BLOCK_SIZE) != 0;

    if (need_recompute) {
        if (ctx->mode == CHIAKI_LIBNX_GHASH_TABLE) {
            /* Allocate table if needed (table-driven mode only) */
            if (!ctx->table) {
                ctx->table = malloc(sizeof(GHashTable));
                if (!ctx->table)
                    return -1;
            }
        }

        /* Store key for future comparison */
        memcpy(ctx->key, key, GMAC_BLOCK_SIZE);

        /* Create AES context and cache it */
        aes128ContextCreate(&ctx->aes_ctx, key, true);

        /* Compute H = AES_K(0) */
        memset(ctx->h, 0, GMAC_BLOCK_SIZE);
        aes128EncryptBlock(&ctx->aes_ctx, ctx->h, ctx->h);

#ifdef CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL
        if (ctx->mode == CHIAKI_LIBNX_GHASH_PMULL) {
            /* Initialize PMULL-based GHASH context */
            ghash_pmull_init(&ctx->pmull_ctx, ctx->h);
        } else
#endif
        {
            /* Initialize table-driven GHASH */
            ghash_table_init(ctx->table, ctx->h);
        }

        ctx->initialized = true;
        ctx->table_init_count++;
    }

    /* Compute J0 (initial counter block) - varies per IV */
    memset(J0, 0, GMAC_BLOCK_SIZE);
    if (iv_len == 12) {
        /* If IV is 96 bits, J0 = IV || 0^31 || 1 */
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        /* Otherwise, J0 = GHASH_H(IV || 0^s || len(IV)) */
#ifdef CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL
        if (ctx->mode == CHIAKI_LIBNX_GHASH_PMULL) {
            ghash_pmull(&ctx->pmull_ctx, iv, iv_len, J0);
        } else
#endif
        {
            ghash_table(ctx->table, iv, iv_len, J0);
        }

        /* Add length block: 64 bits of 0 || 64 bits of IV length in bits */
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
#ifdef CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL
        if (ctx->mode == CHIAKI_LIBNX_GHASH_PMULL) {
            gf128_mul_pmull(J0, J0, ctx->h);
        } else
#endif
        {
            gf128_mul_table(J0, J0, ctx->table);
        }
    }

    /* Initialize GHASH state Y = 0 */
    memset(Y, 0, GMAC_BLOCK_SIZE);

    /* Process AAD through GHASH */
#ifdef CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL
    if (ctx->mode == CHIAKI_LIBNX_GHASH_PMULL) {
        ghash_pmull(&ctx->pmull_ctx, aad, aad_len, Y);
    } else
#endif
    {
        ghash_table(ctx->table, aad, aad_len, Y);
    }

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
#ifdef CHIAKI_LIB_ENABLE_LIBNX_EXPERIMENTAL
    if (ctx->mode == CHIAKI_LIBNX_GHASH_PMULL) {
        gf128_mul_pmull(Y, Y, ctx->h);
    } else
#endif
    {
        gf128_mul_table(Y, Y, ctx->table);
    }

    /* S = Y (final GHASH output) */
    /* Tag = S XOR AES_K(J0) */
    aes128EncryptBlock(&ctx->aes_ctx, S, J0);
    xor_block(S, Y);

    memcpy(tag, S, tag_len);

    return 0;
#else
    /* Fallback to non-cached version when libnx crypto not available */
    (void)ctx;
    return chiaki_gmac_compute(key, iv, iv_len, aad, aad_len, tag, tag_len);
#endif
}
