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

#define GMAC_BLOCK_SIZE 16
#define GMAC_TAG_SIZE   16

/**
 * GMAC context for incremental operations
 */
typedef struct {
    uint8_t h[GMAC_BLOCK_SIZE];      /* Hash key H = AES_K(0) */
    uint8_t y[GMAC_BLOCK_SIZE];      /* Current GHASH state */
    uint8_t j0[GMAC_BLOCK_SIZE];     /* Initial counter block */
    uint8_t key[GMAC_BLOCK_SIZE];    /* AES key */
    uint64_t aad_len;                /* Total AAD length in bits */
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

#endif /* CHIAKI_GMAC_H */
