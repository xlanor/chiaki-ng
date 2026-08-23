// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL
#include "store_parse.h"

bool chiaki_aia_store_resolve(uintptr_t value, uint32_t cert_size,
	uintptr_t base, uint32_t bufsize, uint32_t *offset_out)
{
	if(!offset_out || bufsize == 0 || cert_size == 0 || value == 0)
		return false;

	if(base <= (uintptr_t)bufsize)
		return false;

	uintptr_t offset;
	if(value >= base && (value - base) < (uintptr_t)bufsize)
		offset = value - base;
	else if(value < (uintptr_t)bufsize)
		offset = value;
	else
		return false;

	if(offset == 0 || (uintptr_t)cert_size > (uintptr_t)bufsize - offset)
		return false;

	*offset_out = (uint32_t)offset;
	return true;
}

bool chiaki_aia_store_count(uintptr_t first_value,
	uintptr_t base, uint32_t bufsize, uint32_t stride, uint32_t *count_out)
{
	if(!count_out || stride == 0 || bufsize == 0)
		return false;

	if(base <= (uintptr_t)bufsize)
		return false;

	uintptr_t offset;
	if(first_value >= base && (first_value - base) < (uintptr_t)bufsize)
		offset = first_value - base;
	else if(first_value > 0 && first_value < (uintptr_t)bufsize)
		offset = first_value;
	else
		return false;

	if(offset == 0 || offset % stride != 0)
		return false;

	uint32_t count = (uint32_t)(offset / stride);
	if(count == 0 || (uint64_t)count * stride > (uint64_t)bufsize)
		return false;

	*count_out = count;
	return true;
}
