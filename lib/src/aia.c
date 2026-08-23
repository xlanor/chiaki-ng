// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL
#include "aia.h"

#include <chiaki/thread.h>

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AIA_PEM_BEGIN "-----BEGIN CERTIFICATE-----"
#define AIA_MAX_HOPS 4

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

static void aia_free_all(uint8_t **certs, size_t count)
{
	for(size_t i = 0; i < count; i++)
		free(certs[i]);
}

ChiakiErrorCode chiaki_aia_recover_with(
	const uint8_t *leaf_der, size_t leaf_len,
	ChiakiAiaFetch fetch, void *fetch_user,
	const uint8_t *const *roots, const size_t *root_lens, size_t root_count,
	char **pem_out, size_t *pem_len_out, ChiakiLog *log)
{
	if(!leaf_der || leaf_len == 0 || !fetch || !pem_out)
		return CHIAKI_ERR_INVALID_DATA;

	*pem_out = NULL;
	if(pem_len_out)
		*pem_len_out = 0;

	uint8_t *found[AIA_MAX_HOPS];
	size_t found_lens[AIA_MAX_HOPS];
	size_t found_count = 0;

	const uint8_t *current = leaf_der;
	size_t current_len = leaf_len;
	bool complete = false;

	char *leaf_desc = chiaki_aia_cert_describe(leaf_der, leaf_len);
	CHIAKI_LOGI(log, "aia: walking from %s", leaf_desc ? leaf_desc : "(unreadable certificate)");
	free(leaf_desc);

	for(size_t hop = 0; hop < AIA_MAX_HOPS; hop++)
	{
		if(chiaki_aia_path_completes(leaf_der, leaf_len,
				(const uint8_t *const *)found, found_lens, found_count,
				roots, root_lens, root_count, log))
		{
			complete = true;
			break;
		}

		char *url = chiaki_aia_issuer_url(current, current_len);
		if(!url)
		{
			CHIAKI_LOGW(log, "aia: certificate names no issuer to fetch, cannot continue");
			break;
		}

		if(strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)
		{
			CHIAKI_LOGW(log, "aia: refusing non-http issuer URL");
			free(url);
			break;
		}

		CHIAKI_LOGI(log, "aia: fetching issuer %zu from %s", hop + 1, url);
		uint8_t *der = NULL;
		size_t der_len = 0;
		bool got = fetch(url, &der, &der_len, fetch_user);
		free(url);

		if(!got || !der || der_len == 0)
		{
			CHIAKI_LOGW(log, "aia: issuer fetch failed");
			free(der);
			break;
		}

		char *desc = chiaki_aia_cert_describe(der, der_len);
		CHIAKI_LOGI(log, "aia:   hop %zu -> %s", hop + 1, desc ? desc : "(unreadable certificate)");
		free(desc);

		found[found_count] = der;
		found_lens[found_count] = der_len;
		found_count++;
		current = der;
		current_len = der_len;
	}

	if(!complete)
	{
		CHIAKI_LOGW(log, "aia: could not complete the chain after %zu fetch(es)", found_count);
		aia_free_all(found, found_count);
		return CHIAKI_ERR_INVALID_DATA;
	}

	if(found_count == 0)
	{
		CHIAKI_LOGI(log, "aia: chain already complete, nothing to recover");
		return CHIAKI_ERR_SUCCESS;
	}

	char *bundle = NULL;
	size_t bundle_len = 0;
	for(size_t i = 0; i < found_count; i++)
	{
		size_t one_len = 0;
		char *one = chiaki_aia_der_to_pem(found[i], found_lens[i], &one_len);
		if(!one)
			continue;

		char *grown = (char *)realloc(bundle, bundle_len + one_len + 1);
		if(!grown)
		{
			free(one);
			break;
		}
		memcpy(grown + bundle_len, one, one_len);
		bundle = grown;
		bundle_len += one_len;
		bundle[bundle_len] = 0;
		free(one);
	}

	aia_free_all(found, found_count);

	if(!bundle || bundle_len == 0)
	{
		free(bundle);
		return CHIAKI_ERR_MEMORY;
	}

	CHIAKI_LOGI(log, "aia: path complete after %zu hop(s), %zu byte bundle", found_count, bundle_len);
	*pem_out = bundle;
	if(pem_len_out)
		*pem_len_out = bundle_len;
	return CHIAKI_ERR_SUCCESS;
}

typedef struct
{
	uint8_t *data;
	size_t len;
	bool failed;
} AiaDownload;

static size_t aia_download_write(void *contents, size_t size, size_t nmemb, void *userp)
{
	AiaDownload *dl = (AiaDownload *)userp;
	size_t total = size * nmemb;
	if(dl->failed)
		return 0;
	if(dl->len + total > 64 * 1024)
	{
		dl->failed = true;
		return 0;
	}
	uint8_t *grown = (uint8_t *)realloc(dl->data, dl->len + total);
	if(!grown)
	{
		dl->failed = true;
		return 0;
	}
	memcpy(grown + dl->len, contents, total);
	dl->data = grown;
	dl->len += total;
	return total;
}

static bool aia_fetch_curl(const char *url, uint8_t **der_out, size_t *der_len_out, void *user)
{
	(void)user;
	CURL *curl = curl_easy_init();
	if(!curl)
		return false;

	AiaDownload dl = { NULL, 0, false };
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, aia_download_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &dl);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

	CURLcode res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	if(res != CURLE_OK || dl.failed || !dl.data || dl.len == 0)
	{
		free(dl.data);
		return false;
	}

	if(dl.data[0] != 0x30)
	{
		uint8_t *der = NULL;
		size_t der_len = 0;
		bool converted = chiaki_aia_pem_to_der((const char *)dl.data, dl.len, &der, &der_len);
		free(dl.data);
		if(!converted)
			return false;
		*der_out = der;
		*der_len_out = der_len;
		return true;
	}

	*der_out = dl.data;
	*der_len_out = dl.len;
	return true;
}

ChiakiErrorCode chiaki_aia_recover(
	const uint8_t *leaf_der, size_t leaf_len,
	char **pem_out, size_t *pem_len_out, ChiakiLog *log)
{
	return chiaki_aia_recover_with(leaf_der, leaf_len, aia_fetch_curl, NULL,
		NULL, NULL, 0, pem_out, pem_len_out, log);
}
