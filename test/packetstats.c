// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <munit.h>
#include <chiaki/packetstats.h>

static void assert_stats(ChiakiPacketStats *stats, bool reset, uint64_t expected_received, uint64_t expected_lost)
{
	uint64_t received;
	uint64_t lost;
	chiaki_packet_stats_get(stats, reset, &received, &lost);
	munit_assert_uint64(received, ==, expected_received);
	munit_assert_uint64(lost, ==, expected_lost);
}

static MunitResult test_sequential_loss(const MunitParameter params[], void *user)
{
	ChiakiPacketStats stats;
	munit_assert_int(chiaki_packet_stats_init(&stats), ==, CHIAKI_ERR_SUCCESS);

	chiaki_packet_stats_push_seq(&stats, 0);
	assert_stats(&stats, true, 1, 0);
	chiaki_packet_stats_push_seq(&stats, 1);
	chiaki_packet_stats_push_seq(&stats, 3);
	assert_stats(&stats, false, 2, 1);

	chiaki_packet_stats_fini(&stats);
	return MUNIT_OK;
}

static MunitResult test_duplicate_does_not_create_loss(const MunitParameter params[], void *user)
{
	ChiakiPacketStats stats;
	munit_assert_int(chiaki_packet_stats_init(&stats), ==, CHIAKI_ERR_SUCCESS);

	chiaki_packet_stats_push_seq(&stats, 0);
	assert_stats(&stats, true, 1, 0);
	chiaki_packet_stats_push_seq(&stats, 1);
	chiaki_packet_stats_push_seq(&stats, 1);
	assert_stats(&stats, false, 2, 0);

	chiaki_packet_stats_fini(&stats);
	return MUNIT_OK;
}

static MunitResult test_sequence_wrap(const MunitParameter params[], void *user)
{
	ChiakiPacketStats stats;
	munit_assert_int(chiaki_packet_stats_init(&stats), ==, CHIAKI_ERR_SUCCESS);

	stats.seq_min = 0xfffe;
	stats.seq_max = 0xfffe;
	chiaki_packet_stats_push_seq(&stats, 0xffff);
	chiaki_packet_stats_push_seq(&stats, 0);
	chiaki_packet_stats_push_seq(&stats, 1);
	assert_stats(&stats, false, 3, 0);

	chiaki_packet_stats_fini(&stats);
	return MUNIT_OK;
}

MunitTest tests_packet_stats[] = {
	{ "/sequential_loss", test_sequential_loss, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/duplicate_does_not_create_loss", test_duplicate_does_not_create_loss, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/sequence_wrap", test_sequence_wrap, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};
