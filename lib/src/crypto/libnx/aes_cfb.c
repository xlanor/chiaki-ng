/*
 * AES-CFB128 implementation for chiaki-ng libnx crypto backend
 *
 * Implements AES-CFB128 mode using libnx's hardware-accelerated AES-ECB.
 * CFB mode turns a block cipher into a stream cipher.
 */

#include "aes_cfb.h"
#include <string.h>

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
#include <switch/crypto/aes.h>
#endif

int chiaki_aes_cfb128_crypt(
    const uint8_t key[16],
    uint8_t iv[16],
    size_t *iv_off,
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    int encrypt)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
    /* Only run for chiaki-ng if libnx crypto is enabled, as we will not rely on openSSL*/
    Aes128Context ctx;
    uint8_t encrypted_iv[AES_BLOCK_SIZE];
    size_t n = iv_off ? *iv_off : 0;

    aes128ContextCreate(&ctx, key, true);

    while (length--) {
        if (n == 0) {
            aes128EncryptBlock(&ctx, encrypted_iv, iv);
        }

        if (encrypt) {
            uint8_t c = *output++ = *input++ ^ encrypted_iv[n];
            iv[n] = c;
        } else {
            uint8_t c = *input++;
            *output++ = c ^ encrypted_iv[n];
            iv[n] = c;
        }

        n = (n + 1) & 0x0F;  /* n = (n + 1) % 16 */
    }

    if (iv_off) {
        *iv_off = n;
    }

    return 0;
#else
    (void)key;
    (void)iv;
    (void)iv_off;
    (void)input;
    (void)output;
    (void)length;
    (void)encrypt;
    return -1;
#endif
}
