// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL
#ifndef CHIAKI_CRYPTO_LIBNX_STORE_PARSE_H
#define CHIAKI_CRYPTO_LIBNX_STORE_PARSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool chiaki_aia_store_resolve(uintptr_t value, uint32_t cert_size,
	uintptr_t base, uint32_t bufsize, uint32_t *offset_out);
bool chiaki_aia_store_count(uintptr_t first_value,
	uintptr_t base, uint32_t bufsize, uint32_t stride, uint32_t *count_out);

#ifdef __cplusplus
}
#endif

#endif
