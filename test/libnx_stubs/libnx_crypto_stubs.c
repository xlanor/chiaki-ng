// libnx crypto stubs - OpenSSL-based implementations for desktop testing
// These provide the low-level crypto primitives that libnx provides on Switch

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "switch/crypto/aes.h"
#include "switch/crypto/hmac.h"
#include "switch/crypto/sha256.h"
#include "switch/services/csrng.h"

// AES-128 implementation
// We store the key in the first 16 bytes of the round_keys array
// and use OpenSSL for actual encryption

void aes128ContextCreate(Aes128Context *out, const void *key, bool is_encryptor)
{
    (void)is_encryptor;  // OpenSSL handles this internally
    memset(out, 0, sizeof(*out));
    memcpy(out->round_keys[0], key, AES_128_KEY_SIZE);
}

void aes128EncryptBlock(const Aes128Context *ctx, void *dst, const void *src)
{
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx)
        return;

    // Use AES-128-ECB for single block encryption
    if (EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_ecb(), NULL, ctx->round_keys[0], NULL) != 1)
        goto cleanup;

    // Disable padding - we're encrypting exactly one block
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    int outlen = 0;
    if (EVP_EncryptUpdate(evp_ctx, dst, &outlen, src, AES_BLOCK_SIZE) != 1)
        goto cleanup;

    int tmplen = 0;
    EVP_EncryptFinal_ex(evp_ctx, (unsigned char*)dst + outlen, &tmplen);

cleanup:
    EVP_CIPHER_CTX_free(evp_ctx);
}

// HMAC-SHA256 implementation

void hmacSha256CalculateMac(void *dst, const void *key, size_t key_size,
                            const void *src, size_t size)
{
    unsigned int md_len = 32;
    HMAC(EVP_sha256(), key, (int)key_size, src, size, dst, &md_len);
}

// SHA-256 implementation

void sha256CalculateHash(void *dst, const void *src, size_t size)
{
    SHA256(src, size, dst);
}

// CSRNG implementation

Result csrngInitialize(void)
{
    // OpenSSL's RAND is always available
    return 0;
}

Result csrngGetRandomBytes(void *out, size_t out_size)
{
    if (RAND_bytes(out, (int)out_size) != 1)
        return 1;  // Error
    return 0;  // Success
}

void csrngExit(void)
{
    // Nothing to clean up with OpenSSL's RAND
}
