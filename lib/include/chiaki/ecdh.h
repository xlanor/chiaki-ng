// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#ifndef CHIAKI_ECDH_H
#define CHIAKI_ECDH_H

#include "common.h"

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHIAKI_ECDH_SECRET_SIZE 32

/* micro-ecc key sizes for secp256k1 */
#define CHIAKI_UECC_PRIVATE_KEY_SIZE 32
#define CHIAKI_UECC_PUBLIC_KEY_SIZE 64  /* micro-ecc format: raw X,Y without 0x04 prefix */

/* secp521r1, used by takion v10 and v13 onwards (feature 5) */
#define CHIAKI_UECC_PRIVATE_KEY_SIZE_P521 66
#define CHIAKI_UECC_PUBLIC_KEY_SIZE_P521 132

#define CHIAKI_ECDH_SECRET_SIZE_MAX CHIAKI_UECC_PRIVATE_KEY_SIZE_P521
#define CHIAKI_ECDH_PUB_KEY_SIZE_MAX (1 + CHIAKI_UECC_PUBLIC_KEY_SIZE_P521)

typedef enum chiaki_ecdh_curve_t
{
	CHIAKI_ECDH_CURVE_SECP256K1 = 0,
	CHIAKI_ECDH_CURVE_SECP521R1
} ChiakiECDHCurve;

typedef struct chiaki_ecdh_t
{
/*
 * WARNING: The following struct layout varies by crypto backend.
 * CHIAKI_LIB_ENABLE_LIBNX_CRYPTO must be defined globally (whole project)
 * to ensure consistent struct sizes.
 */
	ChiakiECDHCurve curve;
#ifdef CHIAKI_LIB_ENABLE_LIBNX_CRYPTO
	/* micro-ecc key storage for libnx backend, sized for the largest curve */
	uint8_t private_key[CHIAKI_UECC_PRIVATE_KEY_SIZE_P521];
	uint8_t public_key[CHIAKI_UECC_PUBLIC_KEY_SIZE_P521];
#else
	/* OpenSSL */
	struct ec_group_st *group;
	struct ec_key_st *key_local;
#endif
} ChiakiECDH;

CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_init(ChiakiECDH *ecdh, ChiakiECDHCurve curve);

/** Size of the shared secret this ECDH produces: 32 for secp256k1, 66 for secp521r1. */
CHIAKI_EXPORT size_t chiaki_ecdh_secret_size(const ChiakiECDH *ecdh);
CHIAKI_EXPORT void chiaki_ecdh_fini(ChiakiECDH *ecdh);
CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_get_local_pub_key(ChiakiECDH *ecdh, uint8_t *key_out, size_t *key_out_size, const uint8_t *handshake_key, uint8_t *sig_out, size_t *sig_out_size);
CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_derive_secret(ChiakiECDH *ecdh, uint8_t *secret_out, const uint8_t *remote_key, size_t remote_key_size, const uint8_t *handshake_key, const uint8_t *remote_sig, size_t remote_sig_size);
CHIAKI_EXPORT ChiakiErrorCode chiaki_ecdh_set_local_key(ChiakiECDH *ecdh, const uint8_t *private_key, size_t private_key_size, const uint8_t *public_key, size_t public_key_size);

#ifdef __cplusplus
}
#endif

#endif // CHIAKI_ECDH_H
