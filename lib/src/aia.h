// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#ifndef CHIAKI_AIA_H
#define CHIAKI_AIA_H

#include <chiaki/common.h>
#include <chiaki/log.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

ChiakiErrorCode chiaki_aia_init(void);
void chiaki_aia_fini(void);

/* Fetches the certificate chain from a host that serves it in full and caches
   the issuers, so a later connection to a host that serves only its leaf can be
   completed. The fetch is made with peer verification enabled, so the chain has
   already been validated by the platform TLS stack before it is cached. */
bool chiaki_aia_repair_from(const char *chain_source_host, const char *target_host, ChiakiLog *log);

bool chiaki_aia_blob_add_pem(const char *pem, size_t pem_len);

/* Returns a snapshot of the cached issuers with its length, or NULL when
   nothing is cached. The caller owns the buffer and must free() it. Copying
   under the lock keeps the data and its length consistent, and means no
   pointer into the cache outlives the call. */
char *chiaki_aia_blob_take(size_t *len_out);

size_t chiaki_aia_blob_len(void);
uint32_t chiaki_aia_blob_generation(void);
void chiaki_aia_blob_reset(void);

#ifdef __cplusplus
}
#endif

#endif
