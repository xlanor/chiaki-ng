// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <chiaki/session.h>
#include <chiaki/ecdh.h>
#include <chiaki/base64.h>

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
#include "crypto/libnx/microecc/uECC.h"
#include <switch/crypto/hmac.h>
#include <switch/services/csrng.h>
#else
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#endif

// memset
#include <string.h>

#include <stdio.h>

#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
/* RNG callback for micro-ecc using libnx csrng */
static int libnx_rng(uint8_t *dest, unsigned size)
{
	csrngGetRandomBytes(dest, size);
	return 1;
}
#endif

CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_init(ChiakiECDH *ecdh)
{
	memset(ecdh, 0, sizeof(ChiakiECDH));
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
	/* Initialize csrng service */
	csrngInitialize();

	/* Set RNG for micro-ecc */
	uECC_set_rng(libnx_rng);

	/* Generate keypair on secp256k1 */
	if (!uECC_make_key(ecdh->public_key, ecdh->private_key, uECC_secp256k1()))
	{
		csrngExit();
		return CHIAKI_ERR_UNKNOWN;
	}

#else
#define CHECK(a) if(!(a)) { chiaki_ecdh_fini(ecdh); return CHIAKI_ERR_UNKNOWN; }
	CHECK(ecdh->group = EC_GROUP_new_by_curve_name(NID_secp256k1));

	CHECK(ecdh->key_local = EC_KEY_new());
	CHECK(EC_KEY_set_group(ecdh->key_local, ecdh->group));
	CHECK(EC_KEY_generate_key(ecdh->key_local));

#undef CHECK
#endif

	return CHIAKI_ERR_SUCCESS;
}

CHIAKI_EXPORT void chiaki_ecdh_fini(ChiakiECDH *ecdh)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
	/* Clear sensitive key material */
	memset(ecdh->private_key, 0, sizeof(ecdh->private_key));
	memset(ecdh->public_key, 0, sizeof(ecdh->public_key));
	csrngExit();
#else
	EC_KEY_free(ecdh->key_local);
	EC_GROUP_free(ecdh->group);
#endif
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_set_local_key(ChiakiECDH *ecdh, const uint8_t *private_key, size_t private_key_size, const uint8_t *public_key, size_t public_key_size)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
	/* Copy private key (32 bytes) */
	if (private_key_size != CHIAKI_UECC_PRIVATE_KEY_SIZE)
		return CHIAKI_ERR_UNKNOWN;
	memcpy(ecdh->private_key, private_key, CHIAKI_UECC_PRIVATE_KEY_SIZE);

	/* Handle public key - may have 0x04 prefix (65 bytes) or be raw (64 bytes) */
	if (public_key_size == 65 && public_key[0] == 0x04)
	{
		/* Skip 0x04 uncompressed point prefix */
		memcpy(ecdh->public_key, public_key + 1, CHIAKI_UECC_PUBLIC_KEY_SIZE);
	}
	else if (public_key_size == CHIAKI_UECC_PUBLIC_KEY_SIZE)
	{
		memcpy(ecdh->public_key, public_key, CHIAKI_UECC_PUBLIC_KEY_SIZE);
	}
	else
	{
		return CHIAKI_ERR_UNKNOWN;
	}

	return CHIAKI_ERR_SUCCESS;
#else
	ChiakiErrorCode err = CHIAKI_ERR_SUCCESS;

	BIGNUM *private_key_bn = BN_bin2bn(private_key, (int)private_key_size, NULL);
	if(!private_key_bn)
		return CHIAKI_ERR_UNKNOWN;

	EC_POINT *public_key_point = EC_POINT_new(ecdh->group);
	if(!public_key_point)
	{
		err = CHIAKI_ERR_UNKNOWN;
		goto error_priv;
	}

	if(!EC_POINT_oct2point(ecdh->group, public_key_point, public_key, public_key_size, NULL))
	{
		err = CHIAKI_ERR_UNKNOWN;
		goto error_pub;
	}

	if(!EC_KEY_set_private_key(ecdh->key_local, private_key_bn))
	{
		err = CHIAKI_ERR_UNKNOWN;
		goto error_pub;
	}

	if(!EC_KEY_set_public_key(ecdh->key_local, public_key_point))
	{
		err = CHIAKI_ERR_UNKNOWN;
		goto error_pub;
	}

error_pub:
	EC_POINT_free(public_key_point);
error_priv:
	BN_free(private_key_bn);
	return err;
#endif
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_get_local_pub_key(ChiakiECDH *ecdh, uint8_t *key_out, size_t *key_out_size, const uint8_t *handshake_key, uint8_t *sig_out, size_t *sig_out_size)
{
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
	/* Export public key in uncompressed format: 0x04 || X || Y */
	key_out[0] = 0x04;
	memcpy(key_out + 1, ecdh->public_key, CHIAKI_UECC_PUBLIC_KEY_SIZE);
	*key_out_size = 1 + CHIAKI_UECC_PUBLIC_KEY_SIZE;  /* 65 bytes */

	/* Compute HMAC-SHA256 signature of the public key */
	hmacSha256CalculateMac(sig_out, handshake_key, CHIAKI_HANDSHAKE_KEY_SIZE, key_out, *key_out_size);
	*sig_out_size = 32;

	return CHIAKI_ERR_SUCCESS;
#else
	const EC_POINT *point = EC_KEY_get0_public_key(ecdh->key_local);
	if(!point)
		return CHIAKI_ERR_UNKNOWN;

	*key_out_size = EC_POINT_point2oct(ecdh->group, point, POINT_CONVERSION_UNCOMPRESSED, key_out, *key_out_size, NULL);
	if(!(*key_out_size))
		return CHIAKI_ERR_UNKNOWN;

	if(!HMAC(EVP_sha256(), handshake_key, CHIAKI_HANDSHAKE_KEY_SIZE, key_out, *key_out_size, sig_out, (unsigned int *)sig_out_size))
		return CHIAKI_ERR_UNKNOWN;
	return CHIAKI_ERR_SUCCESS;

#endif
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_derive_secret(ChiakiECDH *ecdh, uint8_t *secret_out, const uint8_t *remote_key, size_t remote_key_size, const uint8_t *handshake_key, const uint8_t *remote_sig, size_t remote_sig_size)
{
	//compute DH shared key
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
	const uint8_t *remote_pub;
	uint8_t remote_pub_buf[CHIAKI_UECC_PUBLIC_KEY_SIZE];

	/* Handle remote public key format */
	if (remote_key_size == 65 && remote_key[0] == 0x04)
	{
		/* Skip 0x04 uncompressed point prefix */
		remote_pub = remote_key + 1;
	}
	else if (remote_key_size == CHIAKI_UECC_PUBLIC_KEY_SIZE)
	{
		remote_pub = remote_key;
	}
	else
	{
		return CHIAKI_ERR_UNKNOWN;
	}

	/* Compute ECDH shared secret */
	if (!uECC_shared_secret(remote_pub, ecdh->private_key, secret_out, uECC_secp256k1()))
	{
		return CHIAKI_ERR_UNKNOWN;
	}

	(void)handshake_key;
	(void)remote_sig;
	(void)remote_sig_size;

	return CHIAKI_ERR_SUCCESS;

#else
	EC_POINT *remote_public_key = EC_POINT_new(ecdh->group);
	if(!remote_public_key)
		return CHIAKI_ERR_UNKNOWN;

	if(!EC_POINT_oct2point(ecdh->group, remote_public_key, remote_key, remote_key_size, NULL))
	{
		EC_POINT_free(remote_public_key);
		return CHIAKI_ERR_UNKNOWN;
	}

	int r = ECDH_compute_key(secret_out, CHIAKI_ECDH_SECRET_SIZE, remote_public_key, ecdh->key_local, NULL);

	EC_POINT_free(remote_public_key);

	if(r != CHIAKI_ECDH_SECRET_SIZE)
		return CHIAKI_ERR_UNKNOWN;

	return CHIAKI_ERR_SUCCESS;
#endif
}
