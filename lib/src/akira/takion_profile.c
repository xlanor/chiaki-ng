// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <chiaki/akira/takion_profile.h>

CHIAKI_EXPORT bool chiaki_akira_takion_feature_supported(unsigned int feature, unsigned int version)
{
	switch(version)
	{
		case 9:
			return feature < 5;
		case 10:
			return feature < 6 && ((0x2fu >> feature) & 1u);
		case 11:
			return feature < 7 && ((0x5fu >> feature) & 1u);
		case 12:
			return feature < 8 && ((0xdfu >> feature) & 1u);
		case 13:
		case 14:
			return feature < 8;
		case 15:
		case 16:
		case 17:
			return feature < 13;
		case 18:
			return feature < 16;
		case 19:
			return feature < 17;
		case 20:
			return feature < 19;
		default:
			return false;
	}
}

CHIAKI_EXPORT size_t chiaki_akira_takion_ext_header_size(unsigned int version, uint8_t base_type)
{
	if(!chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_EXTENDED_HEADER, version))
		return 0;
	if(!chiaki_akira_takion_packet_type_has_ext_header(base_type))
		return 0;
	return CHIAKI_AKIRA_TAKION_EXT_HEADER_SIZE;
}

CHIAKI_EXPORT size_t chiaki_akira_takion_data_message_prefix(unsigned int version, uint8_t data_type)
{
	if(!chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_EXTENDED_HEADER, version))
		return 0;
	switch(data_type)
	{
		case 5:
		case 7:
		case 9:
		case 11:
		case 12:
		case 13:
			return CHIAKI_AKIRA_TAKION_EXT_HEADER_SIZE;
		default:
			return 0;
	}
}

CHIAKI_EXPORT void chiaki_akira_takion_ext_header_write(uint8_t *buf, uint32_t timestamp, uint32_t counter)
{
	buf[0] = (uint8_t)(timestamp >> 24);
	buf[1] = (uint8_t)(timestamp >> 16);
	buf[2] = (uint8_t)(timestamp >> 8);
	buf[3] = (uint8_t)timestamp;
	buf[4] = (uint8_t)(counter >> 24);
	buf[5] = (uint8_t)(counter >> 16);
	buf[6] = (uint8_t)(counter >> 8);
	buf[7] = (uint8_t)counter;
}

CHIAKI_EXPORT void chiaki_akira_takion_ext_header_read(const uint8_t *buf, uint32_t *timestamp, uint32_t *counter)
{
	if(timestamp)
		*timestamp = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
			| ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
	if(counter)
		*counter = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16)
			| ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
}

CHIAKI_EXPORT bool chiaki_akira_takion_version_known(unsigned int version)
{
	return version == 7 || (version >= 9 && version <= CHIAKI_AKIRA_TAKION_VERSION_MAX);
}

CHIAKI_EXPORT bool chiaki_akira_takion_version_implemented(unsigned int version)
{
	if(!chiaki_akira_takion_version_known(version))
		return false;
	for(unsigned int feature = 0; feature < 32; feature++)
	{
		if(!chiaki_akira_takion_feature_supported(feature, version))
			continue;
		if(feature > CHIAKI_AKIRA_TAKION_FEATURE_MAX_IMPLEMENTED)
			return false;
	}
	return true;
}

CHIAKI_EXPORT unsigned int chiaki_akira_takion_version_select(unsigned int base, unsigned int override)
{
	if(!override)
		return base;
	if(!chiaki_akira_takion_version_implemented(override))
		return base;
	return override;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_akira_audio_units_decode(unsigned int version,
	uint16_t units_in_frame_fec, uint16_t units_in_frame_total, size_t data_size,
	ChiakiAkiraAudioUnits *units)
{
	if(!units)
		return CHIAKI_ERR_INVALID_DATA;

	units->unit_size = 0;
	units->unit_size_derived = 0;
	units->source_units_count = 0;
	units->fec_units_count = 0;

	if(!units_in_frame_total)
		return CHIAKI_ERR_INVALID_DATA;

	if(data_size % (size_t)units_in_frame_total)
		return CHIAKI_ERR_INVALID_DATA;

	units->unit_size_derived = data_size / (size_t)units_in_frame_total;

	if(chiaki_akira_takion_feature_supported(CHIAKI_AKIRA_TAKION_FEATURE_AV_UNIT_COUNT_ONLY, version))
	{
		uint16_t source = units_in_frame_fec & CHIAKI_AKIRA_AV_UNIT_SOURCE_MASK;
		if(!source || source > units_in_frame_total)
			return CHIAKI_ERR_INVALID_DATA;
		units->source_units_count = source;
		units->fec_units_count = units_in_frame_total - source;
		units->unit_size = units->unit_size_derived;
		return CHIAKI_ERR_SUCCESS;
	}

	units->unit_size = (size_t)(units_in_frame_fec >> 8);
	units->fec_units_count = (uint16_t)((units_in_frame_fec >> 4) & 0xf);
	units->source_units_count = (uint16_t)(units_in_frame_fec & 0xf);
	return CHIAKI_ERR_SUCCESS;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_akira_takion_ext_message_header_read(const uint8_t *buf,
	size_t buf_size, ChiakiAkiraTakionExtMessageHeader *header)
{
	if(buf_size < CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_SIZE)
		return CHIAKI_ERR_BUF_TOO_SMALL;

	header->key_pos = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16)
		| ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
	header->header_version = buf[8];
	header->payload_type = buf[9];
	header->flags = (uint16_t)(((uint16_t)buf[10] << 8) | (uint16_t)buf[11]);

	if(header->header_version != CHIAKI_AKIRA_TAKION_EXT_MESSAGE_HEADER_VERSION)
		return CHIAKI_ERR_INVALID_DATA;

	return CHIAKI_ERR_SUCCESS;
}

CHIAKI_EXPORT void chiaki_akira_takion_ext_message_header_write(uint8_t *buf,
	const ChiakiAkiraTakionExtMessageHeader *header)
{
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = (uint8_t)(header->key_pos >> 24);
	buf[5] = (uint8_t)(header->key_pos >> 16);
	buf[6] = (uint8_t)(header->key_pos >> 8);
	buf[7] = (uint8_t)header->key_pos;
	buf[8] = header->header_version;
	buf[9] = header->payload_type;
	buf[10] = (uint8_t)(header->flags >> 8);
	buf[11] = (uint8_t)header->flags;
}
