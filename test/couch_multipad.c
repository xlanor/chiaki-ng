// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <munit.h>

#include <chiaki/common.h>
#include <chiaki/ctrl.h>
#include <chiaki/session.h>
#include <chiaki/takion.h>

#include <takion.pb.h>
#include <pb_encode.h>
#include <pb_decode.h>

#include <string.h>

#define TAKION_PACKET_TYPE_FEEDBACK_STATE 0xb
#define TAKION_PACKET_TYPE_FEEDBACK_HISTORY 0xc

static MunitResult test_feedback_state_header_event_count(const MunitParameter params[], void *user)
{
	uint8_t buf[0xc];
	memset(buf, 0xaa, sizeof(buf));
	chiaki_takion_feedback_header_format(buf, TAKION_PACKET_TYPE_FEEDBACK_STATE, 0x1234, 1);
	munit_assert_uint8(buf[0], ==, TAKION_PACKET_TYPE_FEEDBACK_STATE);
	munit_assert_uint8(buf[1], ==, 0x12);
	munit_assert_uint8(buf[2], ==, 0x34);
	munit_assert_uint8(buf[3], ==, 1);
	munit_assert_uint32(*((uint32_t *)(buf + 4)), ==, 0);
	munit_assert_uint32(*((uint32_t *)(buf + 8)), ==, 0);
	return MUNIT_OK;
}

static MunitResult test_feedback_header_history_type(const MunitParameter params[], void *user)
{
	uint8_t buf[0xc];
	memset(buf, 0xaa, sizeof(buf));
	chiaki_takion_feedback_header_format(buf, TAKION_PACKET_TYPE_FEEDBACK_HISTORY, 0x00ff, 7);
	munit_assert_uint8(buf[0], ==, TAKION_PACKET_TYPE_FEEDBACK_HISTORY);
	munit_assert_uint8(buf[1], ==, 0x00);
	munit_assert_uint8(buf[2], ==, 0xff);
	munit_assert_uint8(buf[3], ==, 7);
	return MUNIT_OK;
}

static MunitResult test_uses_controller_id_rule(const MunitParameter params[], void *user)
{
	munit_assert_false(chiaki_couch_uses_controller_id(1));
	munit_assert_true(chiaki_couch_uses_controller_id(2));
	munit_assert_true(chiaki_couch_uses_controller_id(3));
	munit_assert_true(chiaki_couch_uses_controller_id(CHIAKI_COUCH_MAX_PADS));
	return MUNIT_OK;
}

static bool announce_roundtrip(uint8_t pad_count, uint8_t pad, bool *has_id_out, int32_t *id_out)
{
	tkproto_TakionMessage msg;
	memset(&msg, 0, sizeof(msg));
	msg.type = tkproto_TakionMessage_PayloadType_CONTROLLERCONNECTION;
	msg.has_controller_connection_payload = true;
	msg.controller_connection_payload.has_connected = true;
	msg.controller_connection_payload.connected = true;
	msg.controller_connection_payload.has_controller_id = chiaki_couch_uses_controller_id(pad_count);
	msg.controller_connection_payload.controller_id = pad;
	msg.controller_connection_payload.has_controller_type = true;
	msg.controller_connection_payload.controller_type = tkproto_ControllerConnectionPayload_ControllerType_DUALSENSE;

	uint8_t buf[512];
	pb_ostream_t ostream = pb_ostream_from_buffer(buf, sizeof(buf));
	if(!pb_encode(&ostream, tkproto_TakionMessage_fields, &msg))
		return false;

	tkproto_TakionMessage decoded;
	memset(&decoded, 0, sizeof(decoded));
	pb_istream_t istream = pb_istream_from_buffer(buf, ostream.bytes_written);
	if(!pb_decode(&istream, tkproto_TakionMessage_fields, &decoded))
		return false;
	if(!decoded.has_controller_connection_payload)
		return false;
	*has_id_out = decoded.controller_connection_payload.has_controller_id;
	*id_out = decoded.controller_connection_payload.controller_id;
	return true;
}

static MunitResult test_announce_single_pad_no_id(const MunitParameter params[], void *user)
{
	bool has_id = true;
	int32_t id = -1;
	munit_assert_true(announce_roundtrip(1, 0, &has_id, &id));
	munit_assert_false(has_id);
	return MUNIT_OK;
}

static MunitResult test_announce_couch_carries_id(const MunitParameter params[], void *user)
{
	for(uint8_t pad = 0; pad < CHIAKI_COUCH_MAX_PADS; pad++)
	{
		bool has_id = false;
		int32_t id = -1;
		munit_assert_true(announce_roundtrip(CHIAKI_COUCH_MAX_PADS, pad, &has_id, &id));
		munit_assert_true(has_id);
		munit_assert_int32(id, ==, pad);
	}
	return MUNIT_OK;
}

static MunitResult test_ps5_user_code_parse(const MunitParameter params[], void *user)
{
	const uint8_t payload[] = { 1, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
		'3', '4', '5', '6', '7', '8', '9', '0', '1', '2', 0 };
	uint8_t pad = 0;
	char code[CHIAKI_COUCH_USER_CODE_LENGTH + 1] = { 0 };
	munit_assert_true(chiaki_ctrl_couch_parse_user_code(payload, sizeof(payload), &pad, code));
	munit_assert_uint8(pad, ==, 1);
	munit_assert_string_equal(code, "1234567890123456789012");
	return MUNIT_OK;
}

static MunitResult test_ps5_user_code_rejects_malformed(const MunitParameter params[], void *user)
{
	uint8_t payload[CHIAKI_COUCH_USER_CODE_LENGTH + 2] = { 0 };
	payload[0] = 1;
	memset(payload + 1, '1', CHIAKI_COUCH_USER_CODE_LENGTH);
	uint8_t pad = 0;
	char code[CHIAKI_COUCH_USER_CODE_LENGTH + 1] = { 0 };

	munit_assert_false(chiaki_ctrl_couch_parse_user_code(payload, sizeof(payload) - 1, &pad, code));
	payload[5] = 'x';
	munit_assert_false(chiaki_ctrl_couch_parse_user_code(payload, sizeof(payload), &pad, code));
	payload[5] = '1';
	payload[sizeof(payload) - 1] = '1';
	munit_assert_false(chiaki_ctrl_couch_parse_user_code(payload, sizeof(payload), &pad, code));
	return MUNIT_OK;
}

static MunitResult test_ps5_couch_account_selection(const MunitParameter params[], void *user)
{
	ChiakiSession session = { 0 };
	munit_assert_int(chiaki_session_couch_set_account_id(&session, 1, "AAAAAAAAAAA="), ==, CHIAKI_ERR_SUCCESS);
	munit_assert_string_equal(session.connect_info.couch_account_id[1], "AAAAAAAAAAA=");
	munit_assert_int(chiaki_session_couch_set_account_id(&session, 0, "AAAAAAAAAAA="), ==, CHIAKI_ERR_INVALID_DATA);
	munit_assert_int(chiaki_session_couch_set_account_id(&session, 1, "not-an-account"), ==, CHIAKI_ERR_INVALID_DATA);
	return MUNIT_OK;
}

MunitTest tests_couch_multipad[] = {
	{
		"/feedback_state_header_event_count",
		test_feedback_state_header_event_count,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{
		"/feedback_header_history_type",
		test_feedback_header_history_type,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{
		"/uses_controller_id_rule",
		test_uses_controller_id_rule,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{
		"/announce_single_pad_no_id",
		test_announce_single_pad_no_id,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{
		"/announce_couch_carries_id",
		test_announce_couch_carries_id,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{
		"/ps5_user_code_parse",
		test_ps5_user_code_parse,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{
		"/ps5_user_code_rejects_malformed",
		test_ps5_user_code_rejects_malformed,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{
		"/ps5_couch_account_selection",
		test_ps5_couch_account_selection,
		NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL
	},
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};
