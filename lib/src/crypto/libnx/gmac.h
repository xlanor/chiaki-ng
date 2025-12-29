/*
 * GMAC (Galois Message Authentication Code) for chiaki-ng libnx crypto backend
 *
 * Implements GMAC using libnx's hardware-accelerated AES-ECB for the
 * underlying block cipher, with software GHASH for the Galois field operations.
 *
 * Used for message authentication in PlayStation Remote Play streaming.
 */

#ifndef CHIAKI_GMAC_H
#define CHIAKI_GMAC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
#include <switch/crypto/aes.h>
#endif

#define GMAC_BLOCK_SIZE 16
#define GMAC_TAG_SIZE   16

/* Forward declaration for internal GHashTable (defined in gmac.c) */
struct GHashTable;

/**
 * GMAC context for table caching optimization
 *
 * Stores precomputed GHASH tables and AES context to avoid
 * recomputation when the key hasn't changed. This is critical
 * for streaming performance where GMAC is called per-packet
 * but the key only changes every ~45,000 key positions.
 */
typedef struct {
    uint8_t h[GMAC_BLOCK_SIZE];      /* Hash key H = AES_K(0) */
    uint8_t key[GMAC_BLOCK_SIZE];    /* Cached AES key for change detection */
    struct GHashTable *table;        /* Cached GHASH multiplication table (heap) */
    bool initialized;                /* Whether context has valid cached data */
    uint32_t table_init_count;       /* For testing: counts table rebuilds */
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
    Aes128Context aes_ctx;           /* Cached AES context */
#endif
} ChiakiGmacContext;

/**
 * Compute GMAC authentication tag
 *
 * @param key       16-byte AES key
 * @param iv        Initialization vector
 * @param iv_len    IV length in bytes
 * @param aad       Additional authenticated data
 * @param aad_len   AAD length in bytes
 * @param tag       Output buffer for authentication tag
 * @param tag_len   Desired tag length 
 * @return 0 on success, non-zero on error
 */
int chiaki_gmac_compute(
    const uint8_t key[16],
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *tag,
    size_t tag_len
);

/**
 * Initialize GMAC context for table caching
 *
 * @param ctx  Context to initialize
 */
void chiaki_gmac_context_init(ChiakiGmacContext *ctx);

/**
 * Free resources held by GMAC context
 *
 * @param ctx  Context to finalize
 */
void chiaki_gmac_context_fini(ChiakiGmacContext *ctx);

/**
 * Compute GMAC with cached context
 *
 * If the key matches the cached key, reuses precomputed tables.
 * Otherwise, recomputes tables and updates the cache.
 *
 * @param ctx       GMAC context for table caching
 * @param key       16-byte AES key
 * @param iv        Initialization vector
 * @param iv_len    IV length in bytes
 * @param aad       Additional authenticated data
 * @param aad_len   AAD length in bytes
 * @param tag       Output buffer for authentication tag
 * @param tag_len   Desired tag length
 * @return 0 on success, non-zero on error
 */
int chiaki_gmac_compute_cached(
    ChiakiGmacContext *ctx,
    const uint8_t key[16],
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *tag,
    size_t tag_len
);

#endif /* CHIAKI_GMAC_H */
