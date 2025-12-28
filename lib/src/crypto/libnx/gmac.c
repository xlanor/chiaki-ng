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

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
#include <switch/crypto/aes.h>
#endif

/*
 * Precomputed tables for 8-bit GHASH multiplication.
 * - M[256][16]: M[b] = b * H in GF(2^128)
 * - R[256]: Reduction values when a byte overflows during shift
 * Total memory: 4KB + 512 bytes = ~4.5KB
 */
typedef struct {
    uint8_t M[256][GMAC_BLOCK_SIZE];  /* Multiplication table: M[b] = b * H */
    uint16_t R[256];                   /* Reduction table for x^8 shift */
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

    /*
     * Build reduction table for the x^8 shift operation
     *
     * When shifting right by 8 bits, the low byte "falls off" and needs
     * to be folded back in using the reduction polynomial.
     *
     * In GCM, the reduction polynomial is R(x) = x^7 + x^2 + x + 1
     * For overflow byte b, we compute b * x^128 mod P(x) where
     * P(x) = x^128 + x^7 + x^2 + x + 1
     *
     * Since x^128 = R(x) mod P(x), we have:
     * b * x^128 = b * R(x) = sum of (bit_i * x^i * R(x)) for each bit
     *
     * The result spans bytes 0 and 1 (positions x^0 to x^15).
     */
    for (int b = 0; b < 256; b++) {
        /* Extract individual bits (b7 is MSB = 0x80 position) */
        int b7 = (b >> 7) & 1;
        int b6 = (b >> 6) & 1;
        int b5 = (b >> 5) & 1;
        int b4 = (b >> 4) & 1;
        int b3 = (b >> 3) & 1;
        int b2 = (b >> 2) & 1;
        int b1 = (b >> 1) & 1;
        int b0 = b & 1;

        /*
         * Compute reduction for each power of x from x^128 to x^135:
         * x^128 = x^7 + x^2 + x + 1
         * x^129 = x^8 + x^3 + x^2 + x
         * x^130 = x^9 + x^4 + x^3 + x^2
         * x^131 = x^10 + x^5 + x^4 + x^3
         * x^132 = x^11 + x^6 + x^5 + x^4
         * x^133 = x^12 + x^7 + x^6 + x^5
         * x^134 = x^13 + x^8 + x^7 + x^6
         * x^135 = x^14 + x^9 + x^8 + x^7
         *
         * Byte 0 contains x^0 to x^7, Byte 1 contains x^8 to x^15
         * In GCM bit ordering: bit 7 = x^0, bit 6 = x^1, ..., bit 0 = x^7
         */
        uint8_t r0 = ((b7) << 7) |
                     ((b7 ^ b6) << 6) |
                     ((b7 ^ b6 ^ b5) << 5) |
                     ((b6 ^ b5 ^ b4) << 4) |
                     ((b5 ^ b4 ^ b3) << 3) |
                     ((b4 ^ b3 ^ b2) << 2) |
                     ((b3 ^ b2 ^ b1) << 1) |
                     ((b7 ^ b2 ^ b1 ^ b0));

        uint8_t r1 = ((b6 ^ b1 ^ b0) << 7) |
                     ((b5 ^ b0) << 6) |
                     ((b4) << 5) |
                     ((b3) << 4) |
                     ((b2) << 3) |
                     ((b1) << 2) |
                     ((b0) << 1);
        /* bit 0 of r1 (x^15) is always 0 */

        t->R[b] = ((uint16_t)r0 << 8) | r1;
    }
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

        /* Apply reduction for the overflow byte */
        uint16_t r = t->R[overflow];
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
