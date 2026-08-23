// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include "aia.h"

#include <chiaki/thread.h>

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AIA_PEM_BEGIN "-----BEGIN CERTIFICATE-----"
#define AIA_MAX_CHAIN 8

static ChiakiMutex aia_blob_mutex;
static char *aia_blob = NULL;
static size_t aia_blob_size = 0;
static uint32_t aia_blob_gen = 0;

ChiakiErrorCode chiaki_aia_init(void)
{
	return chiaki_mutex_init(&aia_blob_mutex, false);
}

void chiaki_aia_fini(void)
{
	chiaki_aia_blob_reset();
	chiaki_mutex_fini(&aia_blob_mutex);
}

bool chiaki_aia_blob_add_pem(const char *pem, size_t pem_len)
{
	if(!pem || pem_len < sizeof(AIA_PEM_BEGIN) - 1)
		return false;

	if(memcmp(pem, AIA_PEM_BEGIN, sizeof(AIA_PEM_BEGIN) - 1) != 0)
		return false;

	chiaki_mutex_lock(&aia_blob_mutex);

	char *grown = (char *)realloc(aia_blob, aia_blob_size + pem_len + 2);
	if(!grown)
	{
		chiaki_mutex_unlock(&aia_blob_mutex);
		return false;
	}

	memcpy(grown + aia_blob_size, pem, pem_len);
	size_t added = pem_len;
	if(pem[pem_len - 1] != '\n')
		grown[aia_blob_size + added++] = '\n';
	grown[aia_blob_size + added] = 0;

	aia_blob = grown;
	aia_blob_size += added;
	aia_blob_gen++;

	chiaki_mutex_unlock(&aia_blob_mutex);
	return true;
}

char *chiaki_aia_blob_take(size_t *len_out)
{
	chiaki_mutex_lock(&aia_blob_mutex);

	char *copy = NULL;
	if(aia_blob && aia_blob_size)
	{
		copy = (char *)malloc(aia_blob_size + 1);
		if(copy)
		{
			memcpy(copy, aia_blob, aia_blob_size);
			copy[aia_blob_size] = 0;
			if(len_out)
				*len_out = aia_blob_size;
		}
	}
	if(!copy && len_out)
		*len_out = 0;

	chiaki_mutex_unlock(&aia_blob_mutex);
	return copy;
}

size_t chiaki_aia_blob_len(void)
{
	chiaki_mutex_lock(&aia_blob_mutex);
	size_t len = aia_blob_size;
	chiaki_mutex_unlock(&aia_blob_mutex);
	return len;
}

uint32_t chiaki_aia_blob_generation(void)
{
	chiaki_mutex_lock(&aia_blob_mutex);
	uint32_t gen = aia_blob_gen;
	chiaki_mutex_unlock(&aia_blob_mutex);
	return gen;
}

void chiaki_aia_blob_reset(void)
{
	chiaki_mutex_lock(&aia_blob_mutex);
	free(aia_blob);
	aia_blob = NULL;
	aia_blob_size = 0;
	aia_blob_gen++;
	chiaki_mutex_unlock(&aia_blob_mutex);
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

static const char *aia_cert_pem_at(struct curl_certinfo *ci, int index)
{
	if(index >= ci->num_of_certs)
		return NULL;

	for(struct curl_slist *s = ci->certinfo[index]; s; s = s->next)
	{
		if(strncmp(s->data, "Cert:", 5) == 0)
			return s->data + 5;
	}
	return NULL;
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
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, aia_curl_debug);
	curl_easy_setopt(curl, CURLOPT_DEBUGDATA, log);
	/* The cached issuers are imported as trust anchors, so everything rests on
	 * this chain having been validated during the fetch. Demand verification
	 * here rather than inheriting it from a default that could be changed. */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

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
	if(chain_len > AIA_MAX_CHAIN)
	{
		CHIAKI_LOGW(log, "certchain: %s served %d certs, caching the first %d only",
			chain_source_host, chain_len, AIA_MAX_CHAIN);
		chain_len = AIA_MAX_CHAIN;
	}

	size_t cached = 0;
	for(int i = 1; i < chain_len; i++)
	{
		const char *pem = aia_cert_pem_at(ci, i);
		if(pem && chiaki_aia_blob_add_pem(pem, strlen(pem)))
			cached++;
	}
	curl_easy_cleanup(curl);

	if(cached == 0)
	{
		CHIAKI_LOGE(log, "certchain: could not cache any issuer cert from %s", chain_source_host);
		return false;
	}

	CHIAKI_LOGI(log, "certchain: cached %zu issuer cert(s) from %s to repair %s",
		cached, chain_source_host, target_host);
	return true;
}
