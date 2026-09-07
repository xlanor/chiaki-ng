// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <munit.h>

#include <string.h>

#include "crypto/libnx/microecc/uECC.h"
#include "crypto/libnx/microecc/uECC_p521.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#define P521_PRIV_SIZE 66
#define P521_PUB_SIZE 132
#define P521_POINT_SIZE 133

#include "akira_ecdh_p521_vectors.inl"

static int test_rng(uint8_t *dest, unsigned size)
{
	return RAND_bytes(dest, (int)size) == 1;
}

static EC_KEY *openssl_key_from_private(const uint8_t *priv)
{
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
	munit_assert_not_null(group);
	EC_KEY *key = EC_KEY_new();
	munit_assert_not_null(key);
	munit_assert_int(EC_KEY_set_group(key, group), ==, 1);

	BIGNUM *d = BN_bin2bn(priv, P521_PRIV_SIZE, NULL);
	munit_assert_not_null(d);
	munit_assert_int(EC_KEY_set_private_key(key, d), ==, 1);

	EC_POINT *pub = EC_POINT_new(group);
	munit_assert_not_null(pub);
	munit_assert_int(EC_POINT_mul(group, pub, d, NULL, NULL, NULL), ==, 1);
	munit_assert_int(EC_KEY_set_public_key(key, pub), ==, 1);

	EC_POINT_free(pub);
	BN_free(d);
	EC_GROUP_free(group);
	return key;
}

static void openssl_public_octets(const EC_KEY *key, uint8_t *out)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);
	const EC_POINT *point = EC_KEY_get0_public_key(key);
	size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
		out, P521_POINT_SIZE, NULL);
	munit_assert_size(len, ==, P521_POINT_SIZE);
}

static MunitResult test_curve_sizes(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uECC_Curve curve = uECC_p521_secp521r1();
	munit_assert_not_null(curve);
	munit_assert_int(uECC_p521_curve_private_key_size(curve), ==, P521_PRIV_SIZE);
	munit_assert_int(uECC_p521_curve_public_key_size(curve), ==, P521_PUB_SIZE);

	return MUNIT_OK;
}

static MunitResult test_fixed_scalar_matches_openssl(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uint8_t priv[P521_PRIV_SIZE];
	uint8_t pub[P521_PUB_SIZE];
	uECC_Curve curve = uECC_p521_secp521r1();

	for(size_t i = 0; i < sizeof(priv); i++)
		priv[i] = (uint8_t)(0x11u * (i + 1));
	priv[0] = 0x00;
	munit_assert_int(uECC_p521_compute_public_key(priv, pub, curve), ==, 1);

	EC_KEY *key = openssl_key_from_private(priv);
	uint8_t expected[P521_POINT_SIZE];
	openssl_public_octets(key, expected);
	EC_KEY_free(key);

	munit_assert_uint8(expected[0], ==, 0x04);
	munit_assert_memory_equal(P521_PUB_SIZE, pub, expected + 1);

	return MUNIT_OK;
}

static MunitResult test_public_key_matches_openssl(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uECC_Curve curve = uECC_p521_secp521r1();
	uECC_p521_set_rng(test_rng);

	for(int i = 0; i < 32; i++)
	{
		uint8_t priv[P521_PRIV_SIZE];
		uint8_t pub[P521_PUB_SIZE];
		munit_assert_int(uECC_p521_make_key(pub, priv, curve), ==, 1);
		munit_assert_int(uECC_p521_valid_public_key(pub, curve), ==, 1);

		EC_KEY *key = openssl_key_from_private(priv);
		uint8_t expected[P521_POINT_SIZE];
		openssl_public_octets(key, expected);
		EC_KEY_free(key);

		munit_assert_memory_equal(P521_PUB_SIZE, pub, expected + 1);
	}

	return MUNIT_OK;
}

static MunitResult test_shared_secret_matches_openssl(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uECC_Curve curve = uECC_p521_secp521r1();
	uECC_p521_set_rng(test_rng);

	for(int i = 0; i < 32; i++)
	{
		uint8_t priv_a[P521_PRIV_SIZE], pub_a[P521_PUB_SIZE];
		uint8_t priv_b[P521_PRIV_SIZE], pub_b[P521_PUB_SIZE];
		munit_assert_int(uECC_p521_make_key(pub_a, priv_a, curve), ==, 1);
		munit_assert_int(uECC_p521_make_key(pub_b, priv_b, curve), ==, 1);

		uint8_t secret_ab[P521_PRIV_SIZE], secret_ba[P521_PRIV_SIZE];
		munit_assert_int(uECC_p521_shared_secret(pub_b, priv_a, secret_ab, curve), ==, 1);
		munit_assert_int(uECC_p521_shared_secret(pub_a, priv_b, secret_ba, curve), ==, 1);
		munit_assert_memory_equal(P521_PRIV_SIZE, secret_ab, secret_ba);

		EC_KEY *key_a = openssl_key_from_private(priv_a);
		EC_KEY *key_b = openssl_key_from_private(priv_b);
		const EC_GROUP *group = EC_KEY_get0_group(key_a);

		uint8_t secret_openssl[P521_PRIV_SIZE];
		int len = ECDH_compute_key(secret_openssl, sizeof(secret_openssl),
			EC_KEY_get0_public_key(key_b), key_a, NULL);
		munit_assert_int(len, ==, P521_PRIV_SIZE);
		munit_assert_memory_equal(P521_PRIV_SIZE, secret_ab, secret_openssl);

		(void)group;
		EC_KEY_free(key_a);
		EC_KEY_free(key_b);
	}

	return MUNIT_OK;
}

static MunitResult test_interop_with_openssl_peer(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uECC_Curve curve = uECC_p521_secp521r1();
	uECC_p521_set_rng(test_rng);

	for(int i = 0; i < 16; i++)
	{
		uint8_t priv_local[P521_PRIV_SIZE], pub_local[P521_PUB_SIZE];
		munit_assert_int(uECC_p521_make_key(pub_local, priv_local, curve), ==, 1);

		EC_KEY *peer = EC_KEY_new_by_curve_name(NID_secp521r1);
		munit_assert_not_null(peer);
		munit_assert_int(EC_KEY_generate_key(peer), ==, 1);

		uint8_t peer_octets[P521_POINT_SIZE];
		openssl_public_octets(peer, peer_octets);

		uint8_t secret_uecc[P521_PRIV_SIZE];
		munit_assert_int(uECC_p521_shared_secret(peer_octets + 1, priv_local, secret_uecc, curve), ==, 1);

		EC_KEY *local = openssl_key_from_private(priv_local);
		uint8_t secret_openssl[P521_PRIV_SIZE];
		int len = ECDH_compute_key(secret_openssl, sizeof(secret_openssl),
			EC_KEY_get0_public_key(local), peer, NULL);
		munit_assert_int(len, ==, P521_PRIV_SIZE);
		munit_assert_memory_equal(P521_PRIV_SIZE, secret_uecc, secret_openssl);

		EC_KEY_free(local);
		EC_KEY_free(peer);
	}

	return MUNIT_OK;
}

static MunitResult test_known_answer_vectors(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uECC_Curve curve = uECC_p521_secp521r1();

	for(size_t i = 0; i < sizeof(p521_kats) / sizeof(p521_kats[0]); i++)
	{
		const struct p521_kat *kat = &p521_kats[i];

		uint8_t pub[P521_PUB_SIZE];
		munit_assert_int(uECC_p521_compute_public_key(kat->priv, pub, curve), ==, 1);
		munit_assert_memory_equal(P521_PUB_SIZE, pub, kat->pub);

		uint8_t shared[P521_PRIV_SIZE];
		munit_assert_int(uECC_p521_shared_secret(kat_peer_public, kat->priv, shared, curve), ==, 1);
		munit_assert_memory_equal(P521_PRIV_SIZE, shared, kat->shared);
	}

	return MUNIT_OK;
}

static MunitResult test_known_answer_vectors_agree_with_openssl(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
	munit_assert_not_null(group);

	uint8_t peer_octets[P521_POINT_SIZE];
	peer_octets[0] = 0x04;
	memcpy(peer_octets + 1, kat_peer_public, P521_PUB_SIZE);
	EC_POINT *peer_point = EC_POINT_new(group);
	munit_assert_not_null(peer_point);
	munit_assert_int(EC_POINT_oct2point(group, peer_point, peer_octets, sizeof(peer_octets), NULL), ==, 1);

	for(size_t i = 0; i < sizeof(p521_kats) / sizeof(p521_kats[0]); i++)
	{
		const struct p521_kat *kat = &p521_kats[i];

		EC_KEY *key = openssl_key_from_private(kat->priv);
		uint8_t octets[P521_POINT_SIZE];
		openssl_public_octets(key, octets);
		munit_assert_memory_equal(P521_PUB_SIZE, octets + 1, kat->pub);

		uint8_t shared[P521_PRIV_SIZE];
		int len = ECDH_compute_key(shared, sizeof(shared), peer_point, key, NULL);
		munit_assert_int(len, ==, P521_PRIV_SIZE);
		munit_assert_memory_equal(P521_PRIV_SIZE, shared, kat->shared);

		EC_KEY_free(key);
	}

	EC_POINT_free(peer_point);
	EC_GROUP_free(group);
	return MUNIT_OK;
}

static MunitResult test_secp256k1_still_works(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uECC_Curve curve = uECC_secp256k1();
	uECC_set_rng(test_rng);
	munit_assert_int(uECC_curve_private_key_size(curve), ==, 32);
	munit_assert_int(uECC_curve_public_key_size(curve), ==, 64);

	for(int i = 0; i < 16; i++)
	{
		uint8_t priv_a[32], pub_a[64], priv_b[32], pub_b[64];
		munit_assert_int(uECC_make_key(pub_a, priv_a, curve), ==, 1);
		munit_assert_int(uECC_make_key(pub_b, priv_b, curve), ==, 1);

		uint8_t secret_ab[32], secret_ba[32];
		munit_assert_int(uECC_shared_secret(pub_b, priv_a, secret_ab, curve), ==, 1);
		munit_assert_int(uECC_shared_secret(pub_a, priv_b, secret_ba, curve), ==, 1);
		munit_assert_memory_equal(32, secret_ab, secret_ba);
	}

	return MUNIT_OK;
}

MunitTest tests_akira_ecdh_p521[] = {
	{ "/curve_sizes", test_curve_sizes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/fixed_scalar_matches_openssl", test_fixed_scalar_matches_openssl, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/public_key_matches_openssl", test_public_key_matches_openssl, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/shared_secret_matches_openssl", test_shared_secret_matches_openssl, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/interop_with_openssl_peer", test_interop_with_openssl_peer, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/known_answer_vectors", test_known_answer_vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/known_answer_vectors_agree_with_openssl", test_known_answer_vectors_agree_with_openssl, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/secp256k1_still_works", test_secp256k1_still_works, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};
