// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <chiaki/random.h>

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
#include <switch/services/csrng.h>
#else
#include <openssl/rand.h>
#endif

CHIAKI_EXPORT ChiakiErrorCode chiaki_random_bytes_crypt(uint8_t *buf, size_t buf_size)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
	Result rc = csrngInitialize();
	if(R_FAILED(rc))
		return CHIAKI_ERR_UNKNOWN;

	rc = csrngGetRandomBytes(buf, buf_size);
	csrngExit();

	if(R_FAILED(rc))
		return CHIAKI_ERR_UNKNOWN;

	return CHIAKI_ERR_SUCCESS;

#else
	int r = RAND_bytes(buf, (int)buf_size);
	if(!r)
		return CHIAKI_ERR_UNKNOWN;
	return CHIAKI_ERR_SUCCESS;
#endif
}

CHIAKI_EXPORT uint32_t chiaki_random_32()
{
	uint32_t rand_number;
	chiaki_random_bytes_crypt((uint8_t *)(&rand_number), 4);
	return rand_number;
}
