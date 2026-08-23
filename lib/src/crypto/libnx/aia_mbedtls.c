// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL
#include "../../aia.h"
#include "store_parse.h"

#include <chiaki/thread.h>

#include <switch.h>

#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t AIA_EXT_OID[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
static const uint8_t AIA_CA_ISSUERS_OID[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02 };

#define AIA_GENERALNAME_URI (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6)

static char *aia_uri_from_extension(unsigned char *p, const unsigned char *end)
{
	size_t len;
	if(mbedtls_asn1_get_tag(&p, end, &len,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
		return NULL;

	const unsigned char *seq_end = p + len;
	while(p < seq_end)
	{
		size_t desc_len;
		if(mbedtls_asn1_get_tag(&p, seq_end, &desc_len,
				MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
			return NULL;

		const unsigned char *desc_end = p + desc_len;
		size_t oid_len;
		if(mbedtls_asn1_get_tag(&p, desc_end, &oid_len, MBEDTLS_ASN1_OID) != 0)
			return NULL;

		bool is_ca_issuers = (oid_len == sizeof(AIA_CA_ISSUERS_OID)) &&
			(memcmp(p, AIA_CA_ISSUERS_OID, oid_len) == 0);
		p += oid_len;

		size_t loc_len;
		unsigned char *loc = p;
		if(mbedtls_asn1_get_tag(&loc, desc_end, &loc_len, AIA_GENERALNAME_URI) != 0)
		{
			p = (unsigned char *)desc_end;
			continue;
		}

		if(is_ca_issuers && loc_len > 0 && !memchr(loc, 0, loc_len))
		{
			char *url = (char *)malloc(loc_len + 1);
			if(!url)
				return NULL;
			memcpy(url, loc, loc_len);
			url[loc_len] = 0;
			return url;
		}

		p = (unsigned char *)desc_end;
	}
	return NULL;
}

char *chiaki_aia_issuer_url(const uint8_t *cert_der, size_t cert_len)
{
	if(!cert_der || cert_len == 0)
		return NULL;

	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	char *url = NULL;

	if(mbedtls_x509_crt_parse_der(&crt, cert_der, cert_len) == 0 && crt.v3_ext.len > 0)
	{
		unsigned char *p = crt.v3_ext.p;
		const unsigned char *end = p + crt.v3_ext.len;
		size_t len;

		if(mbedtls_asn1_get_tag(&p, end, &len,
				MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0)
		{
			const unsigned char *exts_end = p + len;
			while(p < exts_end && !url)
			{
				size_t ext_len;
				if(mbedtls_asn1_get_tag(&p, exts_end, &ext_len,
						MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
					break;

				const unsigned char *ext_end = p + ext_len;
				size_t oid_len;
				if(mbedtls_asn1_get_tag(&p, ext_end, &oid_len, MBEDTLS_ASN1_OID) != 0)
					break;

				bool is_aia = (oid_len == sizeof(AIA_EXT_OID)) &&
					(memcmp(p, AIA_EXT_OID, oid_len) == 0);
				p += oid_len;

				int critical = 0;
				mbedtls_asn1_get_bool(&p, ext_end, &critical);

				size_t val_len;
				if(mbedtls_asn1_get_tag(&p, ext_end, &val_len, MBEDTLS_ASN1_OCTET_STRING) != 0)
					break;

				if(is_aia)
					url = aia_uri_from_extension(p, p + val_len);

				p = (unsigned char *)ext_end;
			}
		}
	}

	mbedtls_x509_crt_free(&crt);
	return url;
}

char *chiaki_aia_der_to_pem(const uint8_t *der, size_t der_len, size_t *pem_len_out)
{
	if(!der || der_len == 0)
		return NULL;

	size_t needed = 0;
	mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
		der, der_len, NULL, 0, &needed);
	if(needed == 0)
		return NULL;

	char *out = (char *)malloc(needed);
	if(!out)
		return NULL;

	size_t written = 0;
	if(mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
			der, der_len, (unsigned char *)out, needed, &written) != 0)
	{
		free(out);
		return NULL;
	}

	size_t len = written > 0 ? written - 1 : 0;
	if(pem_len_out)
		*pem_len_out = len;
	return out;
}

static Result aia_get_certificates_raw(void *buffer, u32 size,
	u32 *cert_ids, u32 count, u32 *total_out)
{
	Service *srv = sslGetServiceSession();
	if(!srv)
		return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

	serviceAssumeDomain(srv);
	return serviceDispatchOut(srv, 2, *total_out,
		.buffer_attrs = {
			SfBufferAttr_HipcMapAlias | SfBufferAttr_Out,
			SfBufferAttr_HipcMapAlias | SfBufferAttr_In,
		},
		.buffers = {
			{ buffer, size },
			{ cert_ids, count * sizeof(*cert_ids) },
		},
	);
}

static size_t aia_load_builtin_roots(mbedtls_x509_crt *trust, ChiakiLog *log)
{
	u32 cert_id = (u32)SslCaCertificateId_All;
	u32 bufsize = 0;
	if(R_FAILED(sslGetCertificateBufSize(&cert_id, 1, &bufsize)) || bufsize == 0)
		return 0;

	void *store = calloc(1, bufsize);
	if(!store)
		return 0;

	u32 total = 0;
	bool offsets_only = true;
	Result rc = aia_get_certificates_raw(store, bufsize, &cert_id, 1, &total);
	if(R_FAILED(rc) || total == 0)
	{
		CHIAKI_LOGW(log, "certchain: direct GetCertificates failed: 0x%x, falling back to libnx", rc);
		offsets_only = false;
		total = 0;
		rc = sslGetCertificates(store, bufsize, &cert_id, 1, &total);
	}

	uint8_t *base = (uint8_t *)store;
	SslBuiltInCertificateInfo *raw = (SslBuiltInCertificateInfo *)store;

	if(!offsets_only && R_FAILED(rc))
	{
		u32 recovered = 0;
		if(!chiaki_aia_store_count((uintptr_t)raw[0].cert_data, (uintptr_t)base,
			bufsize, (u32)sizeof(SslBuiltInCertificateInfo), &recovered))
		{
			CHIAKI_LOGE(log, "certchain: store entries are unreadable: 0x%x", rc);
			free(store);
			return 0;
		}
		total = recovered;
	}

	size_t loaded = 0, skipped = 0;
	for(u32 i = 0; i < total; i++)
	{
		if(raw[i].status != SslTrustedCertStatus_EnabledTrusted)
			continue;

		u32 offset = 0;
		if(!chiaki_aia_store_resolve((uintptr_t)raw[i].cert_data, (uint32_t)raw[i].cert_size,
				(uintptr_t)base, bufsize, &offset))
		{
			skipped++;
			continue;
		}

		if(mbedtls_x509_crt_parse_der(trust, base + offset, (size_t)raw[i].cert_size) == 0)
			loaded++;
		else
			skipped++;
	}

	CHIAKI_LOGI(log, "certchain: %zu built-in root(s) loaded, %zu skipped (%u entries, %s)",
		loaded, skipped, total, offsets_only ? "direct" : "recovered");
	free(store);
	return loaded;
}

static ChiakiMutex aia_roots_mutex;
static bool aia_roots_mutex_ready = false;
static mbedtls_x509_crt aia_roots;
static bool aia_roots_loaded = false;

static bool aia_builtin_roots(mbedtls_x509_crt **out, ChiakiLog *log)
{
	if(!aia_roots_mutex_ready)
	{
		if(chiaki_mutex_init(&aia_roots_mutex, false) != CHIAKI_ERR_SUCCESS)
			return false;
		aia_roots_mutex_ready = true;
	}

	chiaki_mutex_lock(&aia_roots_mutex);
	if(!aia_roots_loaded)
	{
		mbedtls_x509_crt_init(&aia_roots);
		aia_roots_loaded = aia_load_builtin_roots(&aia_roots, log) > 0;
	}
	bool ok = aia_roots_loaded;
	if(ok)
		*out = &aia_roots;
	chiaki_mutex_unlock(&aia_roots_mutex);
	return ok;
}

bool chiaki_aia_path_completes(
	const uint8_t *leaf_der, size_t leaf_len,
	const uint8_t *const *candidates, const size_t *candidate_lens, size_t candidate_count,
	const uint8_t *const *roots, const size_t *root_lens, size_t root_count,
	ChiakiLog *log)
{
	if(!leaf_der || leaf_len == 0)
		return false;

	mbedtls_x509_crt chain, trust;
	mbedtls_x509_crt_init(&chain);
	mbedtls_x509_crt_init(&trust);
	mbedtls_x509_crt *builtin = NULL;
	bool ok = false;

	if(mbedtls_x509_crt_parse_der(&chain, leaf_der, leaf_len) != 0)
		goto out;

	for(size_t i = 0; i < candidate_count; i++)
		mbedtls_x509_crt_parse_der(&chain, candidates[i], candidate_lens[i]);

	if(roots && root_lens && root_count > 0)
	{
		size_t added = 0;
		for(size_t i = 0; i < root_count; i++)
		{
			if(mbedtls_x509_crt_parse_der(&trust, roots[i], root_lens[i]) == 0)
				added++;
		}
		if(added == 0)
			goto out;
	}
	else if(!aia_builtin_roots(&builtin, log))
	{
		CHIAKI_LOGE(log, "aia: no usable roots in the built-in store");
		goto out;
	}

	uint32_t flags = 0;
	if(mbedtls_x509_crt_verify(&chain, builtin ? builtin : &trust, NULL, NULL, &flags, NULL, NULL) == 0)
		ok = true;
	else
	{
		char why[128];
		mbedtls_x509_crt_verify_info(why, sizeof(why), "", flags);
		CHIAKI_LOGI(log, "aia: path incomplete (flags 0x%x): %s", flags, why);
	}

out:
	mbedtls_x509_crt_free(&trust);
	mbedtls_x509_crt_free(&chain);
	return ok;
}

bool chiaki_aia_pem_to_der(const char *pem, size_t pem_len, uint8_t **der_out, size_t *der_len_out)
{
	if(!pem || pem_len == 0 || !der_out || !der_len_out)
		return false;

	char *copy = (char *)malloc(pem_len + 1);
	if(!copy)
		return false;
	memcpy(copy, pem, pem_len);
	copy[pem_len] = 0;

	mbedtls_pem_context ctx;
	mbedtls_pem_init(&ctx);
	size_t used = 0;
	bool ok = false;

	if(mbedtls_pem_read_buffer(&ctx, "-----BEGIN CERTIFICATE-----",
			"-----END CERTIFICATE-----", (const unsigned char *)copy, NULL, 0, &used) == 0)
	{
		if(ctx.buf && ctx.buflen > 0)
		{
			uint8_t *der = (uint8_t *)malloc(ctx.buflen);
			if(der)
			{
				memcpy(der, ctx.buf, ctx.buflen);
				*der_out = der;
				*der_len_out = ctx.buflen;
				ok = true;
			}
		}
	}

	mbedtls_pem_free(&ctx);
	free(copy);
	if(!ok)
		*der_len_out = 0;
	return ok;
}

#include <chiaki/random.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

static int aia_entropy(void *user, unsigned char *out, size_t len)
{
	(void)user;
	return chiaki_random_bytes_crypt(out, len) == CHIAKI_ERR_SUCCESS ? 0 : -1;
}

bool chiaki_aia_peek_leaf(const char *host, uint8_t **der_out, size_t *der_len_out, ChiakiLog *log)
{
	if(!host || !der_out || !der_len_out)
		return false;

	mbedtls_net_context net;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context drbg;

	mbedtls_net_init(&net);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&drbg);

	bool ok = false;
	int rc;

	if((rc = mbedtls_ctr_drbg_seed(&drbg, aia_entropy, NULL, NULL, 0)) != 0)
	{
		CHIAKI_LOGE(log, "aia: could not seed the RNG: -0x%x", -rc);
		goto out;
	}

	if((rc = mbedtls_net_connect(&net, host, "443", MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		CHIAKI_LOGW(log, "aia: could not connect to %s: -0x%x", host, -rc);
		goto out;
	}

	if((rc = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
		goto out;

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);

	if((rc = mbedtls_ssl_setup(&ssl, &conf)) != 0)
		goto out;
	if((rc = mbedtls_ssl_set_hostname(&ssl, host)) != 0)
		goto out;

	mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

	while((rc = mbedtls_ssl_handshake(&ssl)) != 0)
	{
		if(rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			CHIAKI_LOGW(log, "aia: handshake with %s failed: -0x%x", host, -rc);
			goto out;
		}
	}

	const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
	if(!peer || !peer->raw.p || peer->raw.len == 0)
	{
		CHIAKI_LOGW(log, "aia: %s served no readable certificate", host);
		goto out;
	}

	uint8_t *der = (uint8_t *)malloc(peer->raw.len);
	if(der)
	{
		memcpy(der, peer->raw.p, peer->raw.len);
		*der_out = der;
		*der_len_out = peer->raw.len;
		ok = true;
		CHIAKI_LOGI(log, "aia: read a %zu byte certificate from %s", peer->raw.len, host);
	}

out:
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&net);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&drbg);
	return ok;
}

char *chiaki_aia_cert_describe(const uint8_t *der, size_t der_len)
{
	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	char *out = NULL;

	if(mbedtls_x509_crt_parse_der(&crt, der, der_len) == 0)
	{
		char subject[256] = { 0 };
		char issuer[256] = { 0 };
		mbedtls_x509_dn_gets(subject, sizeof(subject), &crt.subject);
		mbedtls_x509_dn_gets(issuer, sizeof(issuer), &crt.issuer);

		size_t len = strlen(subject) + strlen(issuer) + 32;
		out = (char *)malloc(len);
		if(out)
			snprintf(out, len, "%s (issued by %s)", subject, issuer);
	}

	mbedtls_x509_crt_free(&crt);
	return out;
}
