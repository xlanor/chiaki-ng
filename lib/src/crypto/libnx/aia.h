// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#ifndef CHIAKI_CRYPTO_LIBNX_AIA_H
#define CHIAKI_CRYPTO_LIBNX_AIA_H

#include <chiaki/log.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool chiaki_aia_chain_is_trusted(
	const uint8_t *const *certs, const size_t *cert_lens, size_t cert_count,
	const char *server_name, ChiakiLog *log);

bool chiaki_aia_blob_add_der(const uint8_t *der, size_t der_len);
const void *chiaki_aia_blob_data(void);
size_t chiaki_aia_blob_len(void);
uint32_t chiaki_aia_blob_generation(void);
void chiaki_aia_blob_reset(void);

bool chiaki_aia_repair_from(const char *chain_source_host, const char *target_host, ChiakiLog *log);

#ifdef __cplusplus
}
#endif

#endif
