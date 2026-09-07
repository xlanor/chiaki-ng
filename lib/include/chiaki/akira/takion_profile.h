// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#ifndef CHIAKI_AKIRA_TAKION_PROFILE_H
#define CHIAKI_AKIRA_TAKION_PROFILE_H

#include <chiaki/common.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHIAKI_AKIRA_TAKION_VERSION_MIN 7
#define CHIAKI_AKIRA_TAKION_VERSION_MAX 20

typedef enum chiaki_akira_takion_feature_t
{
	CHIAKI_AKIRA_TAKION_FEATURE_ECDH_P521 = 5,
	CHIAKI_AKIRA_TAKION_FEATURE_AUDIO_STREAM = 6,
	CHIAKI_AKIRA_TAKION_FEATURE_HAPTICS_STREAM = 7,
	CHIAKI_AKIRA_TAKION_FEATURE_DYNAMIC_RANGE_AUTO = 9,
	CHIAKI_AKIRA_TAKION_FEATURE_PAD_SPEAKER = 10,
	CHIAKI_AKIRA_TAKION_FEATURE_AV_UNIT_COUNT_ONLY = 11,
	CHIAKI_AKIRA_TAKION_FEATURE_EXT_MESSAGE = 13,
	CHIAKI_AKIRA_TAKION_FEATURE_RTT_SYSTEM = 14,
	CHIAKI_AKIRA_TAKION_FEATURE_QUALITY_MESSAGE = 15,
	CHIAKI_AKIRA_TAKION_FEATURE_EXTENDED_HEADER = 17,
	CHIAKI_AKIRA_TAKION_FEATURE_VIDEO_CFG_CLAMP = 18
} ChiakiAkiraTakionFeature;

/**
 * Highest feature number this client handles. Features 0, 8, 12 and 16 have no
 * call sites in the daemon at all, so what actually carries behaviour up to here
 * is 1-7, 9-11, 13-15 and 17-18.
 *
 * 17 (extended header) is the only one of those that changes the wire format, and
 * it is implemented in both directions. 18 is console-side. 13 (ExtMessage) is
 * implemented: the packet is authenticated, decrypted and decoded, and an RTT ping
 * is echoed back as a pong, which is all the console asks of the peer. 14 (RTT
 * probing) still only starts if we put rttConfig in the launch spec, and 15 (the
 * quality message) is ours to send or not; neither is an obligation.
 */
#define CHIAKI_AKIRA_TAKION_FEATURE_MAX_IMPLEMENTED 18

CHIAKI_EXPORT bool chiaki_akira_takion_feature_supported(unsigned int feature, unsigned int version);

CHIAKI_EXPORT bool chiaki_akira_takion_version_known(unsigned int version);

/**
 * Whether this client can actually complete a session at the given version.
 * A version is known long before it is implemented: true when every feature the
 * version enables is one this client handles, i.e. none above
 * CHIAKI_AKIRA_TAKION_FEATURE_MAX_IMPLEMENTED.
 */
CHIAKI_EXPORT bool chiaki_akira_takion_version_implemented(unsigned int version);

/**
 * Resolve the version to announce. Falls back to base when the override is not
 * implemented, so an unsupported override degrades instead of failing the session.
 */
CHIAKI_EXPORT unsigned int chiaki_akira_takion_version_select(unsigned int base, unsigned int override);

/**
 * Feature 17 inserts a fixed 8-byte header immediately after the 1-byte packet
 * type, shifting every field after it. The daemon computes each offset as
 * `1 + 8 * supported(17, version)`, so the shift is uniform rather than per-field.
 * Content is a big-endian 32-bit timestamp followed by a big-endian 32-bit counter
 * that increments once per sent packet.
 */
#define CHIAKI_AKIRA_TAKION_EXT_HEADER_SIZE 8

/**
 * Packet types 0 (control), 4 (handshake) and 8 (client info) never carry the
 * extended header, at any version: their handlers take the raw buffer and return
 * before the header would be read. Those are exactly the packets that must parse
 * before or independently of version negotiation.
 */
static inline bool chiaki_akira_takion_packet_type_has_ext_header(uint8_t base_type)
{
	return base_type != 0 && base_type != 4 && base_type != 8;
}

/**
 * Bytes the extended header occupies for this packet type at this version,
 * i.e. the amount every subsequent field is shifted by. 0 below v20.
 */
CHIAKI_EXPORT size_t chiaki_akira_takion_ext_header_size(unsigned int version, uint8_t base_type);

/**
 * Write the 8 header bytes at buf: big-endian timestamp then big-endian counter,
 * matching the order the daemon's encoder emits them in.
 */
CHIAKI_EXPORT void chiaki_akira_takion_ext_header_write(uint8_t *buf, uint32_t timestamp, uint32_t counter);

/**
 * Read the two fields back out of the 8 header bytes at buf.
 */
CHIAKI_EXPORT void chiaki_akira_takion_ext_header_read(const uint8_t *buf, uint32_t *timestamp, uint32_t *counter);

/**
 * Packet type 14 (ExtMessage) carries its own 12-byte header, immediately after the
 * extended header when there is one. It is laid out like the ordinary takion header
 * but at its own offsets: a 4-byte GMAC tag, then a big-endian key position, then a
 * one-byte header version that the console requires to be 1, a one-byte payload type,
 * and a big-endian 16-bit flag word. The payload protobuf follows.
 *
 * So the mac sits at 1 + ext and the key position at 5 + ext, which is what the
 * offset tables in takion.c encode; everything else about authentication is the same
 * as for any other packet.
 */
#define CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_SIZE 12
#define CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_VERSION 1

/**
 * Bit 0 of the flag word says the payload after the header is encrypted. The console
 * tests exactly this bit before running the payload through the cipher.
 */
#define CHIAKI_AKIRA_TAKION_EXT_MESSAGE_FLAG_ENCRYPTED 0x1

/**
 * Payload type byte. The console's receive path accepts 0 and logs every other value
 * as an unknown message type, so RTT is the only kind it will parse from us.
 */
#define CHIAKI_AKIRA_TAKION_EXT_MESSAGE_TYPE_RTT 0

typedef struct chiaki_akira_takion_ext_message_header_t
{
	uint32_t key_pos;
	uint8_t header_version;
	uint8_t payload_type;
	uint16_t flags;
} ChiakiAkiraTakionExtMessageHeader;

CHIAKI_EXPORT ChiakiErrorCode chiaki_akira_takion_ext_message_header_read(const uint8_t *buf,
	size_t buf_size, ChiakiAkiraTakionExtMessageHeader *header);

CHIAKI_EXPORT void chiaki_akira_takion_ext_message_header_write(uint8_t *buf,
	const ChiakiAkiraTakionExtMessageHeader *header);

/**
 * At versions with feature 11 the AV header's 16-bit unit word no longer carries
 * the unit size (that is derived from data_size / units_in_frame_total). Its low
 * bits hold the source unit count, exactly as the low nibble did at v12; the FEC
 * count is the remainder of the total. Bit 13 is set on every observed packet and
 * is not part of the count, hence the mask.
 */
#define CHIAKI_AKIRA_AV_UNIT_SOURCE_MASK 0x1fffu
/**
 * Bit 13 of that word, set on every packet the console has been observed to send.
 * Outbound packets set it too, so what we encode matches what the console encodes.
 */
#define CHIAKI_AKIRA_AV_UNIT_SOURCE_FLAG 0x2000u

/**
 * At versions with feature 11 the AV sub-tag byte carries flags above the tag:
 * main audio arrives as 0x20 and haptics pad 0 as 0x22, i.e. the v12 tag with
 * bit 5 set. Features 10 and 11 both first appear at v15, so which of the two
 * owns that bit is not yet distinguishable.
 */
#define CHIAKI_AKIRA_AV_TAG_MASK 0x1fu

typedef struct chiaki_akira_audio_units_t
{
	size_t unit_size;
	size_t unit_size_derived;
	uint16_t source_units_count;
	uint16_t fec_units_count;
} ChiakiAkiraAudioUnits;

CHIAKI_EXPORT ChiakiErrorCode chiaki_akira_audio_units_decode(unsigned int version,
	uint16_t units_in_frame_fec, uint16_t units_in_frame_total, size_t data_size,
	ChiakiAkiraAudioUnits *units);

#define CHIAKI_AKIRA_AV_TAG_MAIN 0x00
#define CHIAKI_AKIRA_AV_TAG_VOICE 0x01
#define CHIAKI_AKIRA_AV_TAG_HAPTIC_BASE 0x02
#define CHIAKI_AKIRA_AV_TAG_PAD_SPEAKER_BASE 0x06
#define CHIAKI_AKIRA_AV_PAD_COUNT 4

static inline bool chiaki_akira_av_tag_is_haptics(uint8_t tag)
{
	return tag >= CHIAKI_AKIRA_AV_TAG_HAPTIC_BASE
		&& tag < CHIAKI_AKIRA_AV_TAG_HAPTIC_BASE + CHIAKI_AKIRA_AV_PAD_COUNT;
}

static inline bool chiaki_akira_av_tag_is_pad_speaker(uint8_t tag)
{
	return tag >= CHIAKI_AKIRA_AV_TAG_PAD_SPEAKER_BASE
		&& tag < CHIAKI_AKIRA_AV_TAG_PAD_SPEAKER_BASE + CHIAKI_AKIRA_AV_PAD_COUNT;
}

static inline uint8_t chiaki_akira_av_tag_pad_index(uint8_t tag)
{
	if(chiaki_akira_av_tag_is_haptics(tag))
		return tag - CHIAKI_AKIRA_AV_TAG_HAPTIC_BASE;
	if(chiaki_akira_av_tag_is_pad_speaker(tag))
		return tag - CHIAKI_AKIRA_AV_TAG_PAD_SPEAKER_BASE;
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif
