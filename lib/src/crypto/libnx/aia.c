// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include "aia.h"

#include <switch.h>
#include <bearssl.h>

#include <curl/curl.h>
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AIA_UNIX_EPOCH_DAYS 719528

typedef struct
{
	uint8_t *data;
	size_t len;
	bool failed;
} AiaDnBuf;

static void aia_dn_append(void *ctx, const void *buf, size_t len)
{
	AiaDnBuf *dn = (AiaDnBuf *)ctx;
	if(dn->failed)
		return;

	uint8_t *grown = (uint8_t *)realloc(dn->data, dn->len + len);
	if(!grown)
	{
		dn->failed = true;
		return;
	}

	memcpy(grown + dn->len, buf, len);
	dn->data = grown;
	dn->len += len;
}

static void aia_anchor_free(br_x509_trust_anchor *ta)
{
	free((void *)ta->dn.data);
	free((void *)ta->pkey.key.rsa.n);
	free((void *)ta->pkey.key.rsa.e);
	memset(ta, 0, sizeof(*ta));
}

static bool aia_anchor_from_der(const uint8_t *der, size_t der_len, br_x509_trust_anchor *out)
{
	br_x509_decoder_context dc;
	AiaDnBuf dn = { NULL, 0, false };

	br_x509_decoder_init(&dc, aia_dn_append, &dn);
	br_x509_decoder_push(&dc, der, der_len);

	if(dn.failed || br_x509_decoder_last_error(&dc) != 0 || !br_x509_decoder_isCA(&dc))
		goto fail;

	br_x509_pkey *pkey = br_x509_decoder_get_pkey(&dc);
	if(!pkey || pkey->key_type != BR_KEYTYPE_RSA)
		goto fail;

	uint8_t *n = (uint8_t *)malloc(pkey->key.rsa.nlen);
	uint8_t *e = (uint8_t *)malloc(pkey->key.rsa.elen);
	if(!n || !e)
	{
		free(n);
		free(e);
		goto fail;
	}

	memcpy(n, pkey->key.rsa.n, pkey->key.rsa.nlen);
	memcpy(e, pkey->key.rsa.e, pkey->key.rsa.elen);

	out->dn.data = dn.data;
	out->dn.len = dn.len;
	out->flags = BR_X509_TA_CA;
	out->pkey.key_type = BR_KEYTYPE_RSA;
	out->pkey.key.rsa.n = n;
	out->pkey.key.rsa.nlen = pkey->key.rsa.nlen;
	out->pkey.key.rsa.e = e;
	out->pkey.key.rsa.elen = pkey->key.rsa.elen;
	return true;

fail:
	free(dn.data);
	return false;
}

bool chiaki_aia_chain_is_trusted(
	const uint8_t *const *certs, const size_t *cert_lens, size_t cert_count,
	const char *server_name, ChiakiLog *log)
{
	if(!certs || !cert_lens || cert_count == 0)
		return false;

	u32 cert_id = (u32)SslCaCertificateId_All;
	u32 bufsize = 0;
	Result rc = sslGetCertificateBufSize(&cert_id, 1, &bufsize);
	if(R_FAILED(rc) || bufsize == 0)
	{
		CHIAKI_LOGE(log, "aia: sslGetCertificateBufSize failed: 0x%x", rc);
		return false;
	}

	void *store = malloc(bufsize);
	if(!store)
		return false;

	CHIAKI_LOGI(log, "certchain: store=%p end=%p bufsize=%u (entry stride %zu)",
		store, (void *)((uint8_t *)store + bufsize), bufsize,
		sizeof(SslBuiltInCertificateInfo));

	u32 total = 0;
	rc = sslGetCertificates(store, bufsize, &cert_id, 1, &total);

	uint8_t *base = (uint8_t *)store;
	uint8_t *limit = base + bufsize;
	SslBuiltInCertificateInfo *raw = (SslBuiltInCertificateInfo *)store;

	if(R_FAILED(rc))
	{
		uintptr_t first = (uintptr_t)raw[0].cert_data;
		if(first > (uintptr_t)base && first < (uintptr_t)limit)
			total = (u32)((first - (uintptr_t)base) / sizeof(SslBuiltInCertificateInfo));
		else if(first > 0 && first < bufsize)
			total = (u32)(first / sizeof(SslBuiltInCertificateInfo));

		if(total == 0)
		{
			CHIAKI_LOGE(log, "certchain: sslGetCertificates failed: 0x%x and entries are unreadable", rc);
			free(store);
			return false;
		}

		CHIAKI_LOGW(log, "certchain: sslGetCertificates returned 0x%x, recovered %u entries",
			rc, total);
	}

	size_t normalised = 0;
	for(u32 i = 0; i < total; i++)
	{
		uintptr_t v = (uintptr_t)raw[i].cert_data;
		uint8_t *p = NULL;

		if(v >= (uintptr_t)base && v < (uintptr_t)limit)
			p = (uint8_t *)v;
		else if(v < bufsize)
			p = base + v;

		if(!p || raw[i].cert_size == 0
			|| p + raw[i].cert_size > limit
			|| p[0] != 0x30)
		{
			raw[i].cert_data = NULL;
			raw[i].cert_size = 0;
			continue;
		}

		raw[i].cert_data = p;
		normalised++;
	}

	if(normalised == 0)
	{
		CHIAKI_LOGE(log, "certchain: no usable certificates in the built-in store");
		free(store);
		return false;
	}

	CHIAKI_LOGI(log, "certchain: %zu/%u store entries normalised", normalised, total);

	SslBuiltInCertificateInfo *infos = (SslBuiltInCertificateInfo *)store;
	br_x509_trust_anchor *anchors =
		(br_x509_trust_anchor *)calloc(total, sizeof(br_x509_trust_anchor));
	if(!anchors)
	{
		free(store);
		return false;
	}

	size_t anchor_count = 0;
	size_t skipped_untrusted = 0;
	size_t skipped_unusable = 0;
	for(u32 i = 0; i < total; i++)
	{
		if(infos[i].status != SslTrustedCertStatus_EnabledTrusted)
		{
			skipped_untrusted++;
			continue;
		}

		if(!infos[i].cert_data || infos[i].cert_size == 0)
			continue;

		if(aia_anchor_from_der(infos[i].cert_data, (size_t)infos[i].cert_size,
				&anchors[anchor_count]))
			anchor_count++;
		else
			skipped_unusable++;
	}

	if(anchor_count == 0)
	{
		CHIAKI_LOGE(log, "aia: no usable trust anchors from the built-in store");
		free(anchors);
		free(store);
		return false;
	}

	CHIAKI_LOGI(log, "aia: %zu RSA trust anchors (%u in store, %zu not trusted, %zu non-RSA/unusable)",
		anchor_count, total, skipped_untrusted, skipped_unusable);

	br_x509_minimal_context ctx;
	br_x509_minimal_init(&ctx, &br_sha256_vtable, anchors, anchor_count);
	br_x509_minimal_set_rsa(&ctx, &br_rsa_i31_pkcs1_vrfy);
	br_x509_minimal_set_hash(&ctx, br_sha1_ID, &br_sha1_vtable);
	br_x509_minimal_set_hash(&ctx, br_sha224_ID, &br_sha224_vtable);
	br_x509_minimal_set_hash(&ctx, br_sha256_ID, &br_sha256_vtable);
	br_x509_minimal_set_hash(&ctx, br_sha384_ID, &br_sha384_vtable);
	br_x509_minimal_set_hash(&ctx, br_sha512_ID, &br_sha512_vtable);

	time_t now = time(NULL);
	br_x509_minimal_set_time(&ctx,
		(uint32_t)(now / 86400) + AIA_UNIX_EPOCH_DAYS,
		(uint32_t)(now % 86400));

	const br_x509_class **xc = &ctx.vtable;
	(*xc)->start_chain(xc, server_name);
	for(size_t i = 0; i < cert_count; i++)
	{
		(*xc)->start_cert(xc, (uint32_t)cert_lens[i]);
		(*xc)->append(xc, certs[i], cert_lens[i]);
		(*xc)->end_cert(xc);
	}
	unsigned err = (*xc)->end_chain(xc);

	if(err != 0)
	{
		const char *why = "validation failed";
		switch(err)
		{
			case BR_ERR_X509_UNSUPPORTED:
				why = "unsupported algorithm - this build verifies RSA chains only (BearSSL ec/ not vendored)";
				break;
			case BR_ERR_X509_NOT_TRUSTED:
				why = "chain does not reach a built-in root";
				break;
			case BR_ERR_X509_EXPIRED:
				why = "certificate expired or console clock is wrong";
				break;
			case BR_ERR_X509_BAD_SIGNATURE:
				why = "bad signature";
				break;
			default:
				break;
		}
		CHIAKI_LOGW(log, "aia: chain rejected (x509 err %u): %s", err, why);
	}

	for(size_t i = 0; i < anchor_count; i++)
		aia_anchor_free(&anchors[i]);
	free(anchors);
	free(store);

	return err == 0;
}

typedef struct AiaBlobGen
{
	char *data;
	struct AiaBlobGen *prev;
} AiaBlobGen;

static Mutex aia_blob_mutex;
static AiaBlobGen *aia_blob_head = NULL;
static size_t aia_blob_size = 0;
static uint32_t aia_blob_gen = 0;

bool chiaki_aia_blob_add_der(const uint8_t *der, size_t der_len)
{
	if(!der || der_len == 0)
		return false;

	size_t pem_len = br_pem_encode(NULL, der, der_len, "CERTIFICATE", 0);
	if(pem_len == 0)
		return false;

	mutexLock(&aia_blob_mutex);

	char *fresh = (char *)malloc(aia_blob_size + pem_len + 1);
	if(!fresh)
	{
		mutexUnlock(&aia_blob_mutex);
		return false;
	}

	if(aia_blob_head && aia_blob_size)
		memcpy(fresh, aia_blob_head->data, aia_blob_size);

	br_pem_encode(fresh + aia_blob_size, der, der_len, "CERTIFICATE", 0);

	AiaBlobGen *node = (AiaBlobGen *)malloc(sizeof(AiaBlobGen));
	if(!node)
	{
		free(fresh);
		mutexUnlock(&aia_blob_mutex);
		return false;
	}

	node->data = fresh;
	node->prev = aia_blob_head;
	aia_blob_head = node;
	aia_blob_size += pem_len;
	aia_blob_gen++;

	mutexUnlock(&aia_blob_mutex);
	return true;
}

const void *chiaki_aia_blob_data(void)
{
	mutexLock(&aia_blob_mutex);
	const void *data = aia_blob_head ? aia_blob_head->data : NULL;
	mutexUnlock(&aia_blob_mutex);
	return data;
}

size_t chiaki_aia_blob_len(void)
{
	mutexLock(&aia_blob_mutex);
	size_t len = aia_blob_size;
	mutexUnlock(&aia_blob_mutex);
	return len;
}

uint32_t chiaki_aia_blob_generation(void)
{
	mutexLock(&aia_blob_mutex);
	uint32_t gen = aia_blob_gen;
	mutexUnlock(&aia_blob_mutex);
	return gen;
}

void chiaki_aia_blob_reset(void)
{
	mutexLock(&aia_blob_mutex);
	aia_blob_head = NULL;
	aia_blob_size = 0;
	aia_blob_gen++;
	mutexUnlock(&aia_blob_mutex);
}

typedef struct
{
	uint8_t *data;
	size_t len;
	bool failed;
} AiaBuf;

static void aia_buf_append(void *ctx, const void *src, size_t len)
{
	AiaBuf *buf = (AiaBuf *)ctx;
	if(buf->failed)
		return;

	uint8_t *grown = (uint8_t *)realloc(buf->data, buf->len + len);
	if(!grown)
	{
		buf->failed = true;
		return;
	}

	memcpy(grown + buf->len, src, len);
	buf->data = grown;
	buf->len += len;
}

static size_t aia_curl_write(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t total = size * nmemb;
	AiaBuf *buf = (AiaBuf *)userp;
	aia_buf_append(buf, contents, total);
	return buf->failed ? 0 : total;
}

static bool aia_pem_to_der(const char *pem, size_t pem_len, AiaBuf *out)
{
	br_pem_decoder_context pc;
	br_pem_decoder_init(&pc);
	br_pem_decoder_setdest(&pc, aia_buf_append, out);

	bool in_object = false;
	while(pem_len > 0)
	{
		size_t consumed = br_pem_decoder_push(&pc, pem, pem_len);
		pem += consumed;
		pem_len -= consumed;

		switch(br_pem_decoder_event(&pc))
		{
			case BR_PEM_BEGIN_OBJ:
				in_object = true;
				break;
			case BR_PEM_END_OBJ:
				return in_object && !out->failed && out->len > 0;
			case BR_PEM_ERROR:
				return false;
			default:
				if(consumed == 0)
					return false;
				break;
		}
	}
	return false;
}

static int aia_curl_debug(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
	(void)handle;
	if(type != CURLINFO_TEXT)
		return 0;

	ChiakiLog *log = (ChiakiLog *)userp;
	while(size > 0 && (data[size - 1] == '\n' || data[size - 1] == '\r'))
		size--;
	if(size > 0)
		CHIAKI_LOGI(log, "aia/curl: %.*s", (int)size, data);
	return 0;
}

static bool aia_cert_der_at(struct curl_certinfo *ci, int index, AiaBuf *out)
{
	if(index >= ci->num_of_certs)
		return false;

	for(struct curl_slist *s = ci->certinfo[index]; s; s = s->next)
	{
		if(strncmp(s->data, "Cert:", 5) != 0)
			continue;
		return aia_pem_to_der(s->data + 5, strlen(s->data + 5), out);
	}
	return false;
}

bool chiaki_aia_repair_from(const char *chain_source_host, const char *target_host, ChiakiLog *log)
{
	char url[256];
	snprintf(url, sizeof(url), "https://%s/", chain_source_host);

	CURL *curl = curl_easy_init();
	if(!curl)
		return false;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

	CURLcode res = curl_easy_perform(curl);
	if(res != CURLE_OK)
	{
		CHIAKI_LOGW(log, "certchain: source connection to %s failed: %s",
			chain_source_host, curl_easy_strerror(res));
		curl_easy_cleanup(curl);
		return false;
	}

	struct curl_certinfo *ci = NULL;
	res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);
	if(res != CURLE_OK || !ci || ci->num_of_certs < 2)
	{
		CHIAKI_LOGW(log, "aia: %s returned %d certs, need at least 2",
			chain_source_host, ci ? ci->num_of_certs : -1);
		curl_easy_cleanup(curl);
		return false;
	}

	int chain_len = ci->num_of_certs;
	if(chain_len > 8)
		chain_len = 8;

	AiaBuf certs[8];
	memset(certs, 0, sizeof(certs));
	bool got = true;
	for(int i = 0; i < chain_len; i++)
	{
		if(!aia_cert_der_at(ci, i, &certs[i]))
		{
			got = false;
			break;
		}
	}
	curl_easy_cleanup(curl);

	bool trusted = false;
	if(!got)
		CHIAKI_LOGW(log, "certchain: could not decode the chain from %s", chain_source_host);
	else
	{
		const uint8_t *chain[8];
		size_t chain_lens[8];
		for(int i = 0; i < chain_len; i++)
		{
			chain[i] = certs[i].data;
			chain_lens[i] = certs[i].len;
		}

		trusted = chiaki_aia_chain_is_trusted(chain, chain_lens, (size_t)chain_len,
			chain_source_host, log);

		if(!trusted)
			CHIAKI_LOGE(log, "certchain: chain from %s did not validate, discarding",
				chain_source_host);
		else
		{
			size_t cached = 0;
			for(int i = 1; i < chain_len; i++)
			{
				if(chiaki_aia_blob_add_der(certs[i].data, certs[i].len))
					cached++;
			}

			if(cached == 0)
			{
				CHIAKI_LOGE(log, "certchain: could not cache any issuer cert");
				trusted = false;
			}
			else
				CHIAKI_LOGI(log, "certchain: cached %zu issuer cert(s) from %s to repair %s",
					cached, chain_source_host, target_host);
		}
	}

	for(int i = 0; i < chain_len; i++)
		free(certs[i].data);
	return trusted;
}
