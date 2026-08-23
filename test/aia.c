// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL
#include <munit.h>

#include "../lib/src/aia.h"

#include <stdlib.h>
#include <string.h>

#include "aia_fixtures.inl"

#define AIA_URL "http://aia.test.invalid/intermediate.crt"
#define PEM_BEGIN "-----BEGIN CERTIFICATE-----"

static const uint8_t *const roots[1] = { fx_root_der };
static const size_t root_lens[1] = { sizeof(fx_root_der) };

static bool fetch_real(const char *url, uint8_t **out, size_t *len, void *user)
{
	(void)user;
	munit_assert_string_equal(url, AIA_URL);
	*out = (uint8_t *)malloc(sizeof(fx_inter_der));
	memcpy(*out, fx_inter_der, sizeof(fx_inter_der));
	*len = sizeof(fx_inter_der);
	return true;
}

static bool fetch_forged(const char *url, uint8_t **out, size_t *len, void *user)
{
	(void)url; (void)user;
	*out = (uint8_t *)malloc(sizeof(fx_decoy_der));
	memcpy(*out, fx_decoy_der, sizeof(fx_decoy_der));
	*len = sizeof(fx_decoy_der);
	return true;
}

static bool fetch_fails(const char *url, uint8_t **out, size_t *len, void *user)
{
	(void)url; (void)out; (void)len; (void)user;
	return false;
}

static MunitResult test_aia_issuer_url(const MunitParameter params[], void *user)
{
	(void)params; (void)user;

	char *url = chiaki_aia_issuer_url(fx_leaf_der, sizeof(fx_leaf_der));
	munit_assert_not_null(url);
	munit_assert_string_equal(url, AIA_URL);
	free(url);

	munit_assert_null(chiaki_aia_issuer_url(fx_root_der, sizeof(fx_root_der)));
	munit_assert_null(chiaki_aia_issuer_url(NULL, 0));
	munit_assert_null(chiaki_aia_issuer_url(fx_leaf_der, 4));

	return MUNIT_OK;
}

static MunitResult test_aia_path_completes(const MunitParameter params[], void *user)
{
	(void)params; (void)user;

	const uint8_t *good[1] = { fx_inter_der };
	size_t good_lens[1] = { sizeof(fx_inter_der) };
	const uint8_t *forged[1] = { fx_decoy_der };
	size_t forged_lens[1] = { sizeof(fx_decoy_der) };

	munit_assert_false(chiaki_aia_path_completes(fx_leaf_der, sizeof(fx_leaf_der),
		NULL, NULL, 0, roots, root_lens, 1, NULL));

	munit_assert_true(chiaki_aia_path_completes(fx_leaf_der, sizeof(fx_leaf_der),
		good, good_lens, 1, roots, root_lens, 1, NULL));

	munit_assert_false(chiaki_aia_path_completes(fx_leaf_der, sizeof(fx_leaf_der),
		forged, forged_lens, 1, roots, root_lens, 1, NULL));

	return MUNIT_OK;
}

static MunitResult test_aia_recover_walks(const MunitParameter params[], void *user)
{
	(void)params; (void)user;

	char *pem = NULL;
	size_t pem_len = 0;
	munit_assert_int(chiaki_aia_recover_with(fx_leaf_der, sizeof(fx_leaf_der),
		fetch_real, NULL, roots, root_lens, 1, &pem, &pem_len, NULL), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_not_null(pem);
	munit_assert_size(pem_len, >, 0);
	munit_assert_memory_equal(strlen(PEM_BEGIN), pem, PEM_BEGIN);
	munit_assert_size(strlen(pem), ==, pem_len);
	free(pem);

	return MUNIT_OK;
}

static MunitResult test_aia_recover_rejects_forged(const MunitParameter params[], void *user)
{
	(void)params; (void)user;

	char *pem = (char *)0x1;
	size_t pem_len = 99;
	munit_assert_int(chiaki_aia_recover_with(fx_leaf_der, sizeof(fx_leaf_der),
		fetch_forged, NULL, roots, root_lens, 1, &pem, &pem_len, NULL), !=, CHIAKI_ERR_SUCCESS);
	munit_assert_null(pem);
	munit_assert_size(pem_len, ==, 0);

	pem = (char *)0x1;
	munit_assert_int(chiaki_aia_recover_with(fx_leaf_der, sizeof(fx_leaf_der),
		fetch_fails, NULL, roots, root_lens, 1, &pem, &pem_len, NULL), !=, CHIAKI_ERR_SUCCESS);
	munit_assert_null(pem);

	return MUNIT_OK;
}

static MunitResult test_aia_recover_noop_when_complete(const MunitParameter params[], void *user)
{
	(void)params; (void)user;

	char *pem = (char *)0x1;
	size_t pem_len = 99;
	munit_assert_int(chiaki_aia_recover_with(fx_inter_der, sizeof(fx_inter_der),
		fetch_fails, NULL, roots, root_lens, 1, &pem, &pem_len, NULL), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_null(pem);
	munit_assert_size(pem_len, ==, 0);

	return MUNIT_OK;
}

static MunitResult test_aia_blob_rejects_non_pem(const MunitParameter params[], void *user)
{
	(void)params; (void)user;
	chiaki_aia_blob_reset();

	munit_assert_false(chiaki_aia_blob_add_pem(NULL, 0));
	munit_assert_false(chiaki_aia_blob_add_pem("hello", 5));
	munit_assert_size(chiaki_aia_blob_len(), ==, 0);
	return MUNIT_OK;
}

static MunitResult test_aia_blob_accumulates(const MunitParameter params[], void *user)
{
	(void)params; (void)user;
	chiaki_aia_blob_reset();

	size_t one_len = 0;
	char *one = chiaki_aia_der_to_pem(fx_inter_der, sizeof(fx_inter_der), &one_len);
	munit_assert_not_null(one);
	munit_assert_memory_equal(strlen(PEM_BEGIN), one, PEM_BEGIN);

	munit_assert_true(chiaki_aia_blob_add_pem(one, one_len));
	munit_assert_size(chiaki_aia_blob_len(), ==, one_len);

	size_t taken_len = 0;
	char *taken = chiaki_aia_blob_take(&taken_len);
	munit_assert_not_null(taken);
	munit_assert_size(taken_len, ==, one_len);
	munit_assert_size(strlen(taken), ==, taken_len);

	free(taken);
	free(one);
	chiaki_aia_blob_reset();
	return MUNIT_OK;
}

MunitTest tests_aia[] = {
	{ "/issuer_url", test_aia_issuer_url, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/path_completes", test_aia_path_completes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/recover_walks", test_aia_recover_walks, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/recover_rejects_forged", test_aia_recover_rejects_forged, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/recover_noop_when_complete", test_aia_recover_noop_when_complete, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/blob_rejects_non_pem", test_aia_blob_rejects_non_pem, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/blob_accumulates", test_aia_blob_accumulates, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};
