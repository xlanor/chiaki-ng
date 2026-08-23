// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <munit.h>

#include "../lib/src/aia.h"

#include <stdlib.h>
#include <string.h>

#define PEM_BEGIN "-----BEGIN CERTIFICATE-----"

static const char cert_pem[] =
		"-----BEGIN CERTIFICATE-----\n"
		"MIIDJzCCAg+gAwIBAgIUF6xirwLj++4Vlq7FF5+wYEhhh9YwDQYJKoZIhvcNAQEL\n"
		"BQAwGjEYMBYGA1UEAwwPYWtpcmEgdGVzdCByb290MCAXDTI2MDgyMzAxMzkyNVoY\n"
		"DzIxMjYwNzMwMDEzOTI1WjAaMRgwFgYDVQQDDA9ha2lyYSB0ZXN0IHJvb3QwggEi\n"
		"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdzEEbGS4jPR7rb11UPfCLUFBj\n"
		"cL1UeucLG5eRJPG39/YnsXmiy5oBLOGI+uocKa/QVoa69NH6nYePKysCWy4JG4os\n"
		"qbDqLRP6kmiX1SfYOGZUCYlSXEi+Zxa2Ki1k+8caDWqZ2Jf1aKXXDgxuud7xWpPP\n"
		"9LoAmTWBuLa2Y4wQhqecFDi7DINQhVlnbNTtovSm1/whM0JRwN4MTYZQv7rAVIZZ\n"
		"YazeEkW0XyI/bB8mn1P7Qo7YyH6r5nUuEjuyGZ2lLkYlvAunHTVJ4p61BpIVY8cJ\n"
		"ALCQZ+k8Ke0CXcKl5vbWLnDdb5/aASVdfuy9Bn29HEgefgP//xqsTCtAuHMBAgMB\n"
		"AAGjYzBhMB0GA1UdDgQWBBQjNetIOHkSuyavUV1uYS2F0cfUfTAfBgNVHSMEGDAW\n"
		"gBQjNetIOHkSuyavUV1uYS2F0cfUfTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB\n"
		"/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAOeio9AD4QSeaLsqgVu5RfdJC+VVv\n"
		"SiCT1yOFDnjFSIzimU+qVoVL2s6cALKDOjwANhgFIOA7KU6TOqJDPazZ7S413Q32\n"
		"wrQuD6mMwshfP5PHltvCWEY2s7aQo475hbKWCbnBg7w4MaByl/W3EE6kx/M2v8f3\n"
		"9D2USo1S6FSgd488H8DdKdLHFYjKeY64zxCNyW9z6HKacgfPjg6izl9GyfTQtbPv\n"
		"DOt0lvBq80LNHJcwnsIw5j/o3JbjWB4T9gL04t25LvDb2s+7veC7Sysq8Sif0rc5\n"
		"Kb024Y7ginPsNyCK4Of3XeY16eYaGZJsO9LOfW1K+CIq2PN5gtoGWTRz2Q==\n"
		"-----END CERTIFICATE-----\n";

static const char other_pem[] =
		"-----BEGIN CERTIFICATE-----\n"
		"MIIDBzCCAe+gAwIBAgIUNV7TT+6yBeThuqJzJkeh2TQrKi8wDQYJKoZIhvcNAQEL\n"
		"BQAwGjEYMBYGA1UEAwwPYWtpcmEgdGVzdCByb290MCAXDTI2MDgyMzAxMzkyNVoY\n"
		"DzIxMjYwNzMwMDEzOTI1WjAbMRkwFwYDVQQDDBBhaWEudGVzdC5pbnZhbGlkMIIB\n"
		"IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiIytTlyTubEVeFz24bMIldJ7\n"
		"dml7E5beslqk3GvCG+xWxi7zW6Ar+IHu2lQEhubZmwlL+1RgxLHYSw7l/noVTSJT\n"
		"3zTu38THyDAKlbbA+Y0taboefHeVmuK6edhJQ/2QojUjgJTS7GQd4277fc1EjaLx\n"
		"juNrt7ALoYSjHYD952UoVWTzleQUUWcHPvEsMd5P5jYuTRbkeolpVUecnLBSQCJH\n"
		"SE7+EF2siJS6T04E519y5YwYAmN8U/c+nR/FCaq6+tTqXSa5a9ldR79zdeSPRBtN\n"
		"KzdT1lRJ1I1rtQ9ukzmeQ/6IHjZpcr+ieHChI57Et6cZfA00GWg5q+mEcth+dwID\n"
		"AQABo0IwQDAdBgNVHQ4EFgQUZaLJJj9Vto7o5X7RIyq2ktyLFsswHwYDVR0jBBgw\n"
		"FoAUIzXrSDh5Ersmr1FdbmEthdHH1H0wDQYJKoZIhvcNAQELBQADggEBACpu8F6/\n"
		"+FJaFkGbiYxzm39BXRyr89HpCS3myM5oUIBiQnC8MJFCx4HRgS8W89ndH4pMRCWZ\n"
		"q7LOEQquC1c6FfZ7BGss1L5iemkYOTBhLmm+V0yZjnetz1K5OSSmWtmaxL5Q0SL0\n"
		"ZMp59GacfvTA//MFbCHeCsme6Enw3kZbJmUlddbls0vL+TzTPYzoapXPYhOZkUHN\n"
		"LiKuw9pQVCmiChcN3d5qLLYVYYzmcHIWarCcH/FVC3ET2BxJkGWKZMk8eDQiZQhW\n"
		"tDchm9rPVjBlTgIwZljKRFxABfUUcFOABvug5GNue8V4ix/363JVbnhwoav1CTTZ\n"
		"9w9AWdM4VXKfeV0=\n"
		"-----END CERTIFICATE-----\n";

static MunitResult test_aia_blob_rejects_non_pem(const MunitParameter params[], void *user)
{
	(void)params; (void)user;
	chiaki_aia_blob_reset();

	munit_assert_false(chiaki_aia_blob_add_pem(NULL, 0));
	munit_assert_false(chiaki_aia_blob_add_pem("", 0));
	munit_assert_false(chiaki_aia_blob_add_pem("hello", 5));
	munit_assert_false(chiaki_aia_blob_add_pem(PEM_BEGIN, 5));
	/* a DER buffer must not be mistaken for PEM */
	munit_assert_false(chiaki_aia_blob_add_pem("\x30\x82\x01\x0a", 4));

	munit_assert_size(chiaki_aia_blob_len(), ==, 0);
	{ size_t n = 1; char *empty = chiaki_aia_blob_take(&n); munit_assert_null(empty); munit_assert_size(n, ==, 0); }
	return MUNIT_OK;
}

static MunitResult test_aia_blob_accumulates(const MunitParameter params[], void *user)
{
	(void)params; (void)user;
	chiaki_aia_blob_reset();
	uint32_t gen0 = chiaki_aia_blob_generation();

	munit_assert_true(chiaki_aia_blob_add_pem(cert_pem, strlen(cert_pem)));
	size_t one = chiaki_aia_blob_len();
	munit_assert_size(one, ==, strlen(cert_pem));
	munit_assert_uint32(chiaki_aia_blob_generation(), >, gen0);

	size_t blob_len = 0;
	char *blob = chiaki_aia_blob_take(&blob_len);
	munit_assert_not_null(blob);
	munit_assert_size(blob_len, ==, chiaki_aia_blob_len());
	munit_assert_memory_equal(strlen(PEM_BEGIN), blob, PEM_BEGIN);
	/* curl reads the blob by length, but it must still be a valid C string */
	munit_assert_size(strlen(blob), ==, one);

	munit_assert_true(chiaki_aia_blob_add_pem(other_pem, strlen(other_pem)));
	munit_assert_size(chiaki_aia_blob_len(), ==, one + strlen(other_pem));

	free(blob);
	blob = chiaki_aia_blob_take(&blob_len);
	munit_assert_not_null(blob);
	munit_assert_size(strlen(blob), ==, blob_len);
	/* both certificates must survive: two BEGIN markers, second one intact */
	munit_assert_not_null(strstr(blob, PEM_BEGIN));
	munit_assert_not_null(strstr(blob + one, PEM_BEGIN));

	free(blob);
	chiaki_aia_blob_reset();
	munit_assert_size(chiaki_aia_blob_len(), ==, 0);
	return MUNIT_OK;
}

static MunitResult test_aia_blob_separates_entries(const MunitParameter params[], void *user)
{
	(void)params; (void)user;
	chiaki_aia_blob_reset();

	/* an entry with no trailing newline must not be glued to the next one,
	   which would corrupt both PEM blocks */
	size_t trimmed = strlen(cert_pem);
	while(trimmed > 0 && cert_pem[trimmed - 1] == '\n')
		trimmed--;

	munit_assert_true(chiaki_aia_blob_add_pem(cert_pem, trimmed));
	munit_assert_true(chiaki_aia_blob_add_pem(other_pem, strlen(other_pem)));

	size_t blob_len = 0;
	char *blob = chiaki_aia_blob_take(&blob_len);
	munit_assert_not_null(blob);
	munit_assert_size(blob_len, ==, chiaki_aia_blob_len());
	munit_assert_null(strstr(blob, "-----" PEM_BEGIN));
	const char *second = strstr(blob + 1, PEM_BEGIN);
	munit_assert_not_null(second);
	munit_assert_char(*(second - 1), ==, '\n');

	free(blob);
	chiaki_aia_blob_reset();
	return MUNIT_OK;
}

MunitTest tests_aia[] = {
	{ "/blob_rejects_non_pem", test_aia_blob_rejects_non_pem, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/blob_accumulates", test_aia_blob_accumulates, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/blob_separates_entries", test_aia_blob_separates_entries, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};
