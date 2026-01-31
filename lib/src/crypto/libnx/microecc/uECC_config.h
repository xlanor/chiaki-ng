/*
 * micro-ecc configuration for chiaki-ng
 *
 * This file configures micro-ecc for use in chiaki-ng's libnx crypto backend.
 */

#ifndef UECC_CONFIG_H
#define UECC_CONFIG_H

/* Only enable secp256k1 for PSN*/
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 0
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 0
#define uECC_SUPPORTS_secp256k1 1

#define uECC_SUPPORT_COMPRESSED_POINT 0

#define uECC_OPTIMIZATION_LEVEL 2

#endif /* UECC_CONFIG_H */
