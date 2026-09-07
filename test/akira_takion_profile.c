// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <munit.h>

#include <chiaki/akira/takion_profile.h>
#include <chiaki/ecdh.h>
#include <chiaki/session.h>
#include <chiaki/takion.h>
#include <string.h>
#include <stdlib.h>

struct version_features
{
	unsigned int version;
	uint32_t mask;
};

static const struct version_features expected_ladder[] = {
	{ 9,  0x0001fu },
	{ 10, 0x0002fu },
	{ 11, 0x0005fu },
	{ 12, 0x000dfu },
	{ 13, 0x000ffu },
	{ 14, 0x000ffu },
	{ 15, 0x01fffu },
	{ 16, 0x01fffu },
	{ 17, 0x01fffu },
	{ 18, 0x0ffffu },
	{ 19, 0x1ffffu },
	{ 20, 0x7ffffu }
};

static MunitResult test_feature_ladder(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	for(size_t i = 0; i < sizeof(expected_ladder) / sizeof(expected_ladder[0]); i++)
	{
		unsigned int version = expected_ladder[i].version;
		uint32_t mask = expected_ladder[i].mask;
		for(unsigned int feature = 0; feature < 19; feature++)
		{
			bool expected = ((mask >> feature) & 1u) != 0;
			bool actual = chiaki_akira_takion_feature_supported(feature, version);
			munit_assert_int(actual, ==, expected);
		}
	}

	return MUNIT_OK;
}

static MunitResult test_feature_dead(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	static const unsigned int dead[] = { 0, 8, 12, 16 };
	(void)dead;

	for(unsigned int version = 9; version <= 20; version++)
	{
		munit_assert_false(chiaki_akira_takion_feature_supported(19, version));
		munit_assert_false(chiaki_akira_takion_feature_supported(64, version));
	}

	for(unsigned int feature = 0; feature < 19; feature++)
	{
		munit_assert_false(chiaki_akira_takion_feature_supported(feature, 7));
		munit_assert_false(chiaki_akira_takion_feature_supported(feature, 8));
		munit_assert_false(chiaki_akira_takion_feature_supported(feature, 21));
		munit_assert_false(chiaki_akira_takion_feature_supported(feature, 0));
	}

	return MUNIT_OK;
}

static MunitResult test_feature_named(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	munit_assert_false(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_PAD_SPEAKER, 12));
	munit_assert_true(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_PAD_SPEAKER, 15));

	munit_assert_false(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_AV_UNIT_COUNT_ONLY, 12));
	munit_assert_true(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_AV_UNIT_COUNT_ONLY, 15));

	munit_assert_false(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_ECDH_P521, 12));
	munit_assert_true(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_ECDH_P521, 13));
	munit_assert_true(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_ECDH_P521, 10));
	munit_assert_false(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_ECDH_P521, 11));

	munit_assert_false(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_EXTENDED_HEADER, 19));
	munit_assert_true(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_EXTENDED_HEADER, 20));

	munit_assert_false(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_EXT_MESSAGE, 17));
	munit_assert_true(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_EXT_MESSAGE, 18));

	return MUNIT_OK;
}

static MunitResult test_v19_is_noop(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	for(unsigned int feature = 0; feature < 19; feature++)
	{
		if(feature == 16)
			continue;
		munit_assert_int(chiaki_akira_takion_feature_supported(feature, 18), ==,
			chiaki_akira_takion_feature_supported(feature, 19));
	}

	return MUNIT_OK;
}

static MunitResult test_audio_units_legacy(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	ChiakiAkiraAudioUnits units;
	uint16_t fec_word = (uint16_t)((0x40 << 8) | (2 << 4) | 1);

	ChiakiErrorCode err = chiaki_akira_audio_units_decode(12, fec_word, 3, 3 * 0x40, &units);
	munit_assert_int(err, ==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(units.unit_size, ==, 0x40);
	munit_assert_uint16(units.fec_units_count, ==, 2);
	munit_assert_uint16(units.source_units_count, ==, 1);
	munit_assert_size(units.unit_size_derived, ==, 0x40);

	return MUNIT_OK;
}

static MunitResult test_audio_units_derivation_matches_header(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	for(size_t unit_size = 1; unit_size <= 0xff; unit_size++)
	{
		for(uint16_t fec_units = 0; fec_units <= 0xf; fec_units++)
		{
			uint16_t total = (uint16_t)(fec_units + 1);
			uint16_t fec_word = (uint16_t)((unit_size << 8) | (fec_units << 4) | 1);
			size_t data_size = unit_size * total;

			ChiakiAkiraAudioUnits units;
			ChiakiErrorCode err = chiaki_akira_audio_units_decode(12, fec_word, total, data_size, &units);
			munit_assert_int(err, ==, CHIAKI_ERR_SUCCESS);
			munit_assert_size(units.unit_size, ==, unit_size);
			munit_assert_size(units.unit_size_derived, ==, units.unit_size);
		}
	}

	return MUNIT_OK;
}

static MunitResult test_audio_units_v15_equivalent(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	for(size_t unit_size = 1; unit_size <= 0xff; unit_size++)
	{
		for(uint16_t source_units = 1; source_units <= 0xf; source_units++)
		{
			for(uint16_t fec_units = 0; fec_units + source_units <= 0xf; fec_units++)
			{
			uint16_t total = (uint16_t)(source_units + fec_units);
			size_t data_size = unit_size * total;

			uint16_t legacy_word = (uint16_t)((unit_size << 8) | (fec_units << 4) | source_units);
			ChiakiAkiraAudioUnits legacy;
			munit_assert_int(chiaki_akira_audio_units_decode(12, legacy_word, total, data_size, &legacy),
				==, CHIAKI_ERR_SUCCESS);

			ChiakiAkiraAudioUnits modern;
			munit_assert_int(chiaki_akira_audio_units_decode(15, source_units, total, data_size, &modern),
				==, CHIAKI_ERR_SUCCESS);

			munit_assert_size(modern.unit_size, ==, legacy.unit_size);
			munit_assert_uint16(modern.fec_units_count, ==, legacy.fec_units_count);
			munit_assert_uint16(modern.source_units_count, ==, legacy.source_units_count);
			}
		}
	}

	return MUNIT_OK;
}

static MunitResult test_audio_units_v15_wide(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	ChiakiAkiraAudioUnits units;
	ChiakiErrorCode err = chiaki_akira_audio_units_decode(15, 1, 2, 1024, &units);
	munit_assert_int(err, ==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(units.unit_size, ==, 512);
	munit_assert_uint16(units.fec_units_count, ==, 1);
	munit_assert_uint16(units.source_units_count, ==, 1);

	return MUNIT_OK;
}

static MunitResult test_audio_units_legacy_would_break_at_v15(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uint16_t on_the_wire = 2;
	munit_assert_uint8((uint8_t)(on_the_wire >> 8), ==, 0);

	ChiakiAkiraAudioUnits units;
	munit_assert_int(chiaki_akira_audio_units_decode(15, on_the_wire, 3, 192, &units), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(units.unit_size, ==, 64);

	return MUNIT_OK;
}

static MunitResult test_audio_units_invalid(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	ChiakiAkiraAudioUnits units;

	munit_assert_int(chiaki_akira_audio_units_decode(12, 0x4021, 0, 192, &units), ==, CHIAKI_ERR_INVALID_DATA);
	munit_assert_int(chiaki_akira_audio_units_decode(12, 0x4021, 3, 191, &units), ==, CHIAKI_ERR_INVALID_DATA);
	munit_assert_int(chiaki_akira_audio_units_decode(15, 4, 3, 192, &units), ==, CHIAKI_ERR_INVALID_DATA);
	munit_assert_int(chiaki_akira_audio_units_decode(12, 0x4021, 3, 192, NULL), ==, CHIAKI_ERR_INVALID_DATA);

	return MUNIT_OK;
}

static MunitResult test_audio_units_mismatch_is_visible(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	ChiakiAkiraAudioUnits units;
	uint16_t fec_word = (uint16_t)((0x40 << 8) | (2 << 4) | 1);

	ChiakiErrorCode err = chiaki_akira_audio_units_decode(12, fec_word, 3, 3 * 0x20, &units);
	munit_assert_int(err, ==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(units.unit_size, ==, 0x40);
	munit_assert_size(units.unit_size_derived, ==, 0x20);

	return MUNIT_OK;
}

static MunitResult test_av_tags(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	munit_assert_false(chiaki_akira_av_tag_is_haptics(0));
	munit_assert_false(chiaki_akira_av_tag_is_haptics(1));
	for(uint8_t tag = 2; tag <= 5; tag++)
	{
		munit_assert_true(chiaki_akira_av_tag_is_haptics(tag));
		munit_assert_false(chiaki_akira_av_tag_is_pad_speaker(tag));
		munit_assert_uint8(chiaki_akira_av_tag_pad_index(tag), ==, (uint8_t)(tag - 2));
	}
	for(uint8_t tag = 6; tag <= 9; tag++)
	{
		munit_assert_false(chiaki_akira_av_tag_is_haptics(tag));
		munit_assert_true(chiaki_akira_av_tag_is_pad_speaker(tag));
		munit_assert_uint8(chiaki_akira_av_tag_pad_index(tag), ==, (uint8_t)(tag - 6));
	}
	munit_assert_false(chiaki_akira_av_tag_is_pad_speaker(10));
	munit_assert_false(chiaki_akira_av_tag_is_haptics(10));

	return MUNIT_OK;
}

static MunitResult test_version_known(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	munit_assert_true(chiaki_akira_takion_version_known(7));
	munit_assert_false(chiaki_akira_takion_version_known(8));
	for(unsigned int version = 9; version <= 20; version++)
		munit_assert_true(chiaki_akira_takion_version_known(version));
	munit_assert_false(chiaki_akira_takion_version_known(21));

	return MUNIT_OK;
}

static MunitResult test_version_implemented(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	/* Every version now enables only features this client handles. v20's feature 17
	   changes the wire format and is implemented; 13, 14 and 15 are opt-in and unused. */
	munit_assert_true(chiaki_akira_takion_version_implemented(7));
	munit_assert_true(chiaki_akira_takion_version_implemented(9));
	munit_assert_true(chiaki_akira_takion_version_implemented(10));
	munit_assert_true(chiaki_akira_takion_version_implemented(11));
	munit_assert_true(chiaki_akira_takion_version_implemented(12));
	for(unsigned int version = 13; version <= 17; version++)
		munit_assert_true(chiaki_akira_takion_version_implemented(version));

	for(unsigned int version = 18; version <= 20; version++)
		munit_assert_true(chiaki_akira_takion_version_implemented(version));
	munit_assert_false(chiaki_akira_takion_version_implemented(8));
	munit_assert_false(chiaki_akira_takion_version_implemented(21));

	return MUNIT_OK;
}

static MunitResult test_version_select(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	munit_assert_uint(chiaki_akira_takion_version_select(12, 0), ==, 12);
	munit_assert_uint(chiaki_akira_takion_version_select(12, 12), ==, 12);
	munit_assert_uint(chiaki_akira_takion_version_select(12, 9), ==, 9);
	munit_assert_uint(chiaki_akira_takion_version_select(12, 15), ==, 15);
	munit_assert_uint(chiaki_akira_takion_version_select(12, 17), ==, 17);
	munit_assert_uint(chiaki_akira_takion_version_select(12, 18), ==, 18);
	munit_assert_uint(chiaki_akira_takion_version_select(12, 20), ==, 20);
	munit_assert_uint(chiaki_akira_takion_version_select(9, 99), ==, 9);

	return MUNIT_OK;
}

static ChiakiECDHCurve curve_for_version(unsigned int version)
{
	return chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_ECDH_P521, version)
		? CHIAKI_ECDH_CURVE_SECP521R1
		: CHIAKI_ECDH_CURVE_SECP256K1;
}

static MunitResult test_ecdh_curve_for_version(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	/* The daemon's per-version feature bitmaps are not monotonic: feature 5 is set
	   at v10, cleared again at v11 and v12, then set from v13 onwards. */
	static const unsigned int p521_versions[] = { 10, 13, 14, 15, 16, 17, 18, 19, 20 };

	for(unsigned int v = 7; v <= CHIAKI_AKIRA_TAKION_VERSION_MAX; v++)
	{
		bool expect_p521 = false;
		for(size_t i = 0; i < sizeof(p521_versions) / sizeof(*p521_versions); i++)
		{
			if(p521_versions[i] == v)
			{
				expect_p521 = true;
				break;
			}
		}
		munit_assert_int(curve_for_version(v), ==,
			expect_p521 ? CHIAKI_ECDH_CURVE_SECP521R1 : CHIAKI_ECDH_CURVE_SECP256K1);
	}

	/* The two versions chiaki actually negotiates today must stay on secp256k1. */
	munit_assert_int(curve_for_version(9), ==, CHIAKI_ECDH_CURVE_SECP256K1);
	munit_assert_int(curve_for_version(12), ==, CHIAKI_ECDH_CURVE_SECP256K1);

	return MUNIT_OK;
}

static MunitResult test_ecdh_curve_unchanged_for_defaults(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	/* The base versions chiaki announces without an override. Enabling v15 must not
	   move either of them off secp256k1, which is the only ECDH path proven in the
	   field. Reaching P-521 has to stay an explicit opt-in. */
	munit_assert_int(curve_for_version(9), ==, CHIAKI_ECDH_CURVE_SECP256K1);
	munit_assert_int(curve_for_version(12), ==, CHIAKI_ECDH_CURVE_SECP256K1);

	munit_assert_uint(chiaki_akira_takion_version_select(9, 0), ==, 9);
	munit_assert_uint(chiaki_akira_takion_version_select(12, 0), ==, 12);

	return MUNIT_OK;
}

static MunitResult test_ecdh_secret_size_by_curve(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	ChiakiECDH ecdh;
	munit_assert_int(chiaki_ecdh_init(&ecdh, CHIAKI_ECDH_CURVE_SECP256K1), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(chiaki_ecdh_secret_size(&ecdh), ==, CHIAKI_ECDH_SECRET_SIZE);
	munit_assert_size(chiaki_ecdh_secret_size(&ecdh), ==, 32);
	chiaki_ecdh_fini(&ecdh);

	munit_assert_int(chiaki_ecdh_init(&ecdh, CHIAKI_ECDH_CURVE_SECP521R1), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(chiaki_ecdh_secret_size(&ecdh), ==, 66);
	chiaki_ecdh_fini(&ecdh);

	munit_assert_size(CHIAKI_ECDH_SECRET_SIZE_MAX, >=, 66);
	munit_assert_size(CHIAKI_ECDH_PUB_KEY_SIZE_MAX, >=, 133);

	return MUNIT_OK;
}

static MunitResult test_v15_delta_from_v12(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	/* Exactly which features v15 turns on that v12 did not. Every one of these has
	   been traced in the daemon: 5 is P-521 ECDH, 9 skips clearing a console-side
	   flag in sub_21ADC0, 10 stops the padspk stream being rejected in
	   RP_StartAvCapVideo, 11 changes the audio unit header, and 8 and 12 have no
	   call sites at all. */
	static const unsigned int newly_enabled[] = { 5, 8, 9, 10, 11, 12 };

	for(unsigned int feature = 0; feature < 32; feature++)
	{
		bool v12 = chiaki_akira_takion_feature_supported(feature, 12);
		bool v15 = chiaki_akira_takion_feature_supported(feature, 15);
		bool expect_new = false;
		for(size_t i = 0; i < sizeof(newly_enabled) / sizeof(*newly_enabled); i++)
		{
			if(newly_enabled[i] == feature)
			{
				expect_new = true;
				break;
			}
		}
		munit_assert_true(v15 || !v12);
		munit_assert_true((v15 && !v12) == expect_new);
	}

	return MUNIT_OK;
}

static MunitResult test_v15_enables_pad_speaker(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	/* v15 is the first version where the daemon stops rejecting the padspk stream. */
	for(unsigned int version = 7; version < 15; version++)
		munit_assert_false(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_PAD_SPEAKER, version));
	for(unsigned int version = 15; version <= CHIAKI_AKIRA_TAKION_VERSION_MAX; version++)
		munit_assert_true(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_PAD_SPEAKER, version));

	return MUNIT_OK;
}

static MunitResult test_v15_uses_p521(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	munit_assert_int(curve_for_version(15), ==, CHIAKI_ECDH_CURVE_SECP521R1);

	ChiakiECDH ecdh;
	munit_assert_int(chiaki_ecdh_init(&ecdh, curve_for_version(15)), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(chiaki_ecdh_secret_size(&ecdh), ==, 66);

	uint8_t pub[CHIAKI_ECDH_PUB_KEY_SIZE_MAX];
	size_t pub_size = sizeof(pub);
	uint8_t handshake_key[CHIAKI_HANDSHAKE_KEY_SIZE] = { 0 };
	uint8_t sig[32];
	size_t sig_size = sizeof(sig);
	munit_assert_int(chiaki_ecdh_get_local_pub_key(&ecdh, pub, &pub_size, handshake_key, sig, &sig_size),
		==, CHIAKI_ERR_SUCCESS);
	munit_assert_size(pub_size, ==, 133);
	munit_assert_uint8(pub[0], ==, 0x04);

	chiaki_ecdh_fini(&ecdh);

	return MUNIT_OK;
}

static MunitResult test_av_parser_for_version(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(7), ==, chiaki_takion_v7_av_packet_parse);

	for(unsigned int v = 9; v <= 11; v++)
		munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(v), ==, chiaki_takion_v9_av_packet_parse);

	for(unsigned int v = 12; v <= 14; v++)
		munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(v), ==, chiaki_takion_v12_av_packet_parse);

	for(unsigned int v = 15; v <= 19; v++)
		munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(v), ==, chiaki_takion_v15_av_packet_parse);

	munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(20), ==, chiaki_takion_v20_av_packet_parse);

	munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(0), ==, NULL);
	munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(8), ==, NULL);
	munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(21), ==, NULL);

	return MUNIT_OK;
}

static MunitResult test_av_parser_covers_selectable_versions(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	for(unsigned int v = 0; v <= 32; v++)
	{
		if(!chiaki_akira_takion_version_implemented(v))
			continue;
		munit_assert_ptr(chiaki_takion_av_packet_parse_for_version(v), !=, NULL);
	}

	return MUNIT_OK;
}

static MunitResult test_v15_real_audio_packets(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

#include "takion_av_packet_v15_real_audio.inl"

	ChiakiTakionAVPacketParse parse = chiaki_takion_av_packet_parse_for_version(15);
	munit_assert_ptr(parse, ==, chiaki_takion_v15_av_packet_parse);

	for(size_t i = 0; i < sizeof(v15_real_audio_cases) / sizeof(v15_real_audio_cases[0]); i++)
	{
		const struct v15_real_audio_case *c = &v15_real_audio_cases[i];

		uint8_t *buf = calloc(1, c->total_size);
		munit_assert_ptr_not_null(buf);
		memcpy(buf, c->header, sizeof(c->header));

		ChiakiKeyState key_state;
		chiaki_key_state_init(&key_state);

		ChiakiTakionAVPacket packet;
		munit_assert_int(parse(&packet, &key_state, buf, c->total_size), ==, CHIAKI_ERR_SUCCESS);

		munit_assert_false(packet.is_video);
		munit_assert_uint16(packet.packet_index, ==, c->packet_index);
		munit_assert_uint16(packet.frame_index, ==, c->frame_index);
		munit_assert_uint8(packet.codec, ==, c->codec);
		munit_assert_true(packet.av_tag_valid);
		munit_assert_uint8(packet.av_tag, ==, c->av_tag);
		munit_assert_true(packet.is_haptics == c->is_haptics);
		munit_assert_uint16(packet.units_in_frame_total, ==, c->units_in_frame_total);
		munit_assert_uint16(packet.units_in_frame_fec, ==, c->units_in_frame_fec);
		munit_assert_size(packet.data_size, ==, c->data_size);

		ChiakiAkiraAudioUnits units;
		munit_assert_int(chiaki_akira_audio_units_decode(15, packet.units_in_frame_fec,
			packet.units_in_frame_total, packet.data_size, &units), ==, CHIAKI_ERR_SUCCESS);
		munit_assert_uint16(units.source_units_count, ==, c->source_units_count);
		munit_assert_uint16(units.fec_units_count, ==, c->fec_units_count);
		munit_assert_size(units.unit_size, ==, c->unit_size);
		munit_assert_uint16(units.source_units_count + units.fec_units_count, ==, packet.units_in_frame_total);
		munit_assert_size(units.unit_size * packet.units_in_frame_total, ==, packet.data_size);

		free(buf);
	}

	return MUNIT_OK;
}

static MunitResult test_ext_header_size(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	static const uint8_t exempt[] = { 0, 4, 8 };
	static const uint8_t carried[] = { 1, 2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14 };

	for(unsigned int v = 7; v < 20; v++)
	{
		if(!chiaki_akira_takion_version_known(v))
			continue;
		for(uint8_t t = 0; t < 15; t++)
			munit_assert_size(chiaki_akira_takion_ext_header_size(v, t), ==, 0);
	}

	for(size_t i = 0; i < sizeof(exempt); i++)
		munit_assert_size(chiaki_akira_takion_ext_header_size(20, exempt[i]), ==, 0);

	for(size_t i = 0; i < sizeof(carried); i++)
		munit_assert_size(chiaki_akira_takion_ext_header_size(20, carried[i]), ==,
			CHIAKI_AKIRA_TAKION_EXT_HEADER_SIZE);

	return MUNIT_OK;
}

static MunitResult test_ext_message_header_wire_format(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	ChiakiAkiraTakionExtMessageHeader header;
	header.key_pos = 0x11223344u;
	header.header_version = CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_VERSION;
	header.payload_type = 0;
	header.flags = CHIAKI_AKIRA_TAKION_EXT_MESSAGE_FLAG_ENCRYPTED;

	uint8_t buf[CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_SIZE];
	memset(buf, 0xee, sizeof(buf));
	chiaki_akira_takion_ext_message_header_write(buf, &header);

	static const uint8_t expected[] = {
		0x00, 0x00, 0x00, 0x00,
		0x11, 0x22, 0x33, 0x44,
		0x01,
		0x00,
		0x00, 0x01
	};
	munit_assert_size(sizeof(expected), ==, CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_SIZE);
	munit_assert_memory_equal(sizeof(buf), buf, expected);

	ChiakiAkiraTakionExtMessageHeader read;
	memset(&read, 0xcd, sizeof(read));
	munit_assert_int(chiaki_akira_takion_ext_message_header_read(buf, sizeof(buf), &read), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_uint32(read.key_pos, ==, 0x11223344u);
	munit_assert_uint8(read.header_version, ==, 1);
	munit_assert_uint8(read.payload_type, ==, 0);
	munit_assert_uint16(read.flags, ==, CHIAKI_AKIRA_TAKION_EXT_MESSAGE_FLAG_ENCRYPTED);

	return MUNIT_OK;
}

static MunitResult test_ext_message_header_rejects(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	static const uint8_t good[] = {
		0xde, 0xad, 0xbe, 0xef,
		0x00, 0x00, 0x04, 0x00,
		0x01,
		0x00,
		0x00, 0x00
	};

	ChiakiAkiraTakionExtMessageHeader header;
	munit_assert_int(chiaki_akira_takion_ext_message_header_read(good, sizeof(good), &header), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_uint32(header.key_pos, ==, 0x400u);
	munit_assert_uint16(header.flags, ==, 0);

	for(size_t size = 0; size < CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_SIZE; size++)
		munit_assert_int(chiaki_akira_takion_ext_message_header_read(good, size, &header), ==, CHIAKI_ERR_BUF_TOO_SMALL);

	uint8_t bad[sizeof(good)];
	memcpy(bad, good, sizeof(good));
	for(unsigned int v = 0; v < 0x100; v++)
	{
		if(v == CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_VERSION)
			continue;
		bad[8] = (uint8_t)v;
		munit_assert_int(chiaki_akira_takion_ext_message_header_read(bad, sizeof(bad), &header), ==, CHIAKI_ERR_INVALID_DATA);
	}

	return MUNIT_OK;
}

static MunitResult test_ext_header_wire_format(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uint8_t buf[CHIAKI_AKIRA_TAKION_EXT_HEADER_SIZE];
	chiaki_akira_takion_ext_header_write(buf, 0x01020304u, 0xaabbccddu);

	static const uint8_t expected[] = { 0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd };
	munit_assert_memory_equal(sizeof(buf), buf, expected);

	uint32_t timestamp = 0, counter = 0;
	chiaki_akira_takion_ext_header_read(buf, &timestamp, &counter);
	munit_assert_uint32(timestamp, ==, 0x01020304u);
	munit_assert_uint32(counter, ==, 0xaabbccddu);

	chiaki_akira_takion_ext_header_write(buf, 0, 0xffffffffu);
	chiaki_akira_takion_ext_header_read(buf, &timestamp, &counter);
	munit_assert_uint32(timestamp, ==, 0);
	munit_assert_uint32(counter, ==, 0xffffffffu);

	return MUNIT_OK;
}

static MunitResult test_v20_shifted_real_audio_packets(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

#include "takion_av_packet_v15_real_audio.inl"

	for(size_t i = 0; i < sizeof(v15_real_audio_cases) / sizeof(v15_real_audio_cases[0]); i++)
	{
		const struct v15_real_audio_case *c = &v15_real_audio_cases[i];
		const size_t ext = CHIAKI_AKIRA_TAKION_EXT_HEADER_SIZE;

		uint8_t *plain = calloc(1, c->total_size);
		uint8_t *shifted = calloc(1, c->total_size + ext);
		munit_assert_ptr_not_null(plain);
		munit_assert_ptr_not_null(shifted);
		memcpy(plain, c->header, sizeof(c->header));

		shifted[0] = plain[0];
		for(size_t b = 0; b < ext; b++)
			shifted[1 + b] = (uint8_t)(0xa0 + b);
		memcpy(shifted + 1 + ext, plain + 1, c->total_size - 1);

		ChiakiKeyState ks_plain, ks_shifted;
		chiaki_key_state_init(&ks_plain);
		chiaki_key_state_init(&ks_shifted);

		ChiakiTakionAVPacket a, b;
		munit_assert_int(chiaki_takion_v15_av_packet_parse(&a, &ks_plain, plain, c->total_size),
			==, CHIAKI_ERR_SUCCESS);
		munit_assert_int(chiaki_takion_v20_av_packet_parse(&b, &ks_shifted, shifted, c->total_size + ext),
			==, CHIAKI_ERR_SUCCESS);

		munit_assert_uint16(b.packet_index, ==, a.packet_index);
		munit_assert_uint16(b.frame_index, ==, a.frame_index);
		munit_assert_uint8(b.codec, ==, a.codec);
		munit_assert_uint8(b.av_tag, ==, a.av_tag);
		munit_assert_true(b.av_tag_valid == a.av_tag_valid);
		munit_assert_true(b.is_haptics == a.is_haptics);
		munit_assert_true(b.is_video == a.is_video);
		munit_assert_uint16(b.units_in_frame_total, ==, a.units_in_frame_total);
		munit_assert_uint16(b.units_in_frame_fec, ==, a.units_in_frame_fec);
		munit_assert_size(b.data_size, ==, a.data_size);
		munit_assert_size(b.data_size, ==, c->data_size);
		munit_assert_ptr(b.data, ==, shifted + (a.data - plain) + ext);

		free(plain);
		free(shifted);
	}

	return MUNIT_OK;
}

static MunitResult test_v20_rejects_truncated_ext_header(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

	uint8_t buf[CHIAKI_AKIRA_TAKION_EXT_HEADER_SIZE];
	buf[0] = 3;

	ChiakiKeyState key_state;
	chiaki_key_state_init(&key_state);

	ChiakiTakionAVPacket packet;
	munit_assert_int(chiaki_takion_v20_av_packet_parse(&packet, &key_state, buf, sizeof(buf)),
		==, CHIAKI_ERR_BUF_TOO_SMALL);

	return MUNIT_OK;
}

static MunitResult test_v12_tag_byte_not_masked(const MunitParameter params[], void *user)
{
	(void)params;
	(void)user;

#include "takion_av_packet_v15_real_audio.inl"

	const struct v15_real_audio_case *c = &v15_real_audio_cases[2];

	uint8_t *buf = calloc(1, c->total_size);
	munit_assert_ptr_not_null(buf);
	memcpy(buf, c->header, sizeof(c->header));

	ChiakiKeyState key_state;
	chiaki_key_state_init(&key_state);

	ChiakiTakionAVPacket packet;
	munit_assert_int(chiaki_takion_v12_av_packet_parse(&packet, &key_state, buf, c->total_size),
		==, CHIAKI_ERR_SUCCESS);

	munit_assert_uint8(packet.av_tag, ==, 0x22);
	munit_assert_false(packet.is_haptics);

	free(buf);

	return MUNIT_OK;
}

MunitTest tests_akira_takion_profile[] = {
	{ "/version_implemented", test_version_implemented, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/version_select", test_version_select, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/feature_ladder", test_feature_ladder, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/feature_dead", test_feature_dead, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/feature_named", test_feature_named, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v19_is_noop", test_v19_is_noop, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/version_known", test_version_known, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/audio_units_legacy", test_audio_units_legacy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/audio_units_derivation_matches_header", test_audio_units_derivation_matches_header, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/audio_units_v15_equivalent", test_audio_units_v15_equivalent, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/audio_units_v15_wide", test_audio_units_v15_wide, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/audio_units_legacy_would_break_at_v15", test_audio_units_legacy_would_break_at_v15, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/audio_units_invalid", test_audio_units_invalid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/audio_units_mismatch_is_visible", test_audio_units_mismatch_is_visible, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/av_tags", test_av_tags, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/ecdh_curve_for_version", test_ecdh_curve_for_version, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/ecdh_curve_unchanged_for_defaults", test_ecdh_curve_unchanged_for_defaults, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/ecdh_secret_size_by_curve", test_ecdh_secret_size_by_curve, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v15_delta_from_v12", test_v15_delta_from_v12, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v15_enables_pad_speaker", test_v15_enables_pad_speaker, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v15_uses_p521", test_v15_uses_p521, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/av_parser_for_version", test_av_parser_for_version, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/ext_header_size", test_ext_header_size, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/ext_header_wire_format", test_ext_header_wire_format, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/ext_message_header_wire_format", test_ext_message_header_wire_format, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/ext_message_header_rejects", test_ext_message_header_rejects, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v20_shifted_real_audio_packets", test_v20_shifted_real_audio_packets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v20_rejects_truncated_ext_header", test_v20_rejects_truncated_ext_header, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/av_parser_covers_selectable_versions", test_av_parser_covers_selectable_versions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v15_real_audio_packets", test_v15_real_audio_packets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "/v12_tag_byte_not_masked", test_v12_tag_byte_not_masked, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};
