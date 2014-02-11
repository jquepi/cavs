/* fips_shatest.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2005.
 */
/* ====================================================================
 * Copyright (c) 2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "fips_utl.h"

static int dgst_test(FILE * out, FILE * in);
static int print_dgst(gnutls_digest_algorithm_t md, FILE * out,
		      unsigned char *Msg, int Msglen);
static int print_monte(gnutls_digest_algorithm_t md, FILE * out,
		       unsigned char *Seed, int SeedLen);

int main(int argc, char **argv)
{
	FILE *in = NULL, *out = NULL;

	int ret = 1;

#ifdef REQUIRE_FIPS
	if (!gnutls_fips140_mode_enabled()) {
		do_print_errors();
		EXIT(1);
	}
#endif

	if (argc == 1)
		in = stdin;
	else
		in = fopen(argv[1], "r");

	if (argc < 2)
		out = stdout;
	else
		out = fopen(argv[2], "w");

	if (!in) {
		fprintf(stderr, "FATAL input initialization error\n");
		goto end;
	}

	if (!out) {
		fprintf(stderr, "FATAL output initialization error\n");
		goto end;
	}

	if (!dgst_test(out, in)) {
		fprintf(stderr, "FATAL digest file processing error\n");
		goto end;
	} else
		ret = 0;

 end:

	if (ret)
		do_print_errors();

	if (in && (in != stdin))
		fclose(in);
	if (out && (out != stdout))
		fclose(out);

	return ret;

}

#define SHA_TEST_MAX_BITS	102400
#define SHA_TEST_MAXLINELEN	(((SHA_TEST_MAX_BITS >> 3) * 2) + 100)

int dgst_test(FILE * out, FILE * in)
{
	gnutls_mac_algorithm_t md;
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	unsigned char *Msg = NULL, *Seed = NULL;
	long MsgLen = -1, Len = -1, SeedLen = -1;
	int ret = 0;
	int lnum = 0;

	olinebuf = malloc(SHA_TEST_MAXLINELEN);
	linebuf = malloc(SHA_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	while (fgets(olinebuf, SHA_TEST_MAXLINELEN, in)) {
		lnum++;
		strcpy(linebuf, olinebuf);
		keyword = linebuf;
		/* Skip leading space */
		while (isspace((unsigned char)*keyword))
			keyword++;

		/* Look for = sign */
		p = strchr(linebuf, '=');

		/* If no = or starts with [ (for [L=20] line) just copy */
		if (!p) {
			fputs(olinebuf, out);
			continue;
		}

		q = p - 1;

		/* Remove trailing space */
		while (isspace((unsigned char)*q))
			*q-- = 0;

		*p = 0;
		value = p + 1;

		/* Remove leading space from value */
		while (isspace((unsigned char)*value))
			value++;

		/* Remove trailing space from value */
		p = value + strlen(value) - 1;
		while (*p == '\n' || *p == '\r' || isspace((unsigned char)*p))
			*p-- = 0;

		if (!strcmp(keyword, "[L") && *p == ']') {
			switch (atoi(value)) {
			case 20:
				md = GNUTLS_MAC_SHA1;
				break;
			case 28:
				md = GNUTLS_MAC_SHA224;
				break;
			case 32:
				md = GNUTLS_MAC_SHA256;
				break;
			case 48:
				md = GNUTLS_MAC_SHA384;
				break;
			case 64:
				md = GNUTLS_MAC_SHA512;
				break;
			default:
				goto parse_error;
			}
		} else if (!strcmp(keyword, "Len")) {
			if (Len != -1)
				goto parse_error;
			Len = atoi(value);
			if (Len < 0)
				goto parse_error;
			if (Len > SHA_TEST_MAX_BITS)
				goto parse_error;
			if (Len & 0x7)
				goto parse_error;
			MsgLen = Len >> 3;
		}

		else if (!strcmp(keyword, "Msg")) {
			long tmplen;
			if (strlen(value) & 1)
				*(--value) = '0';
			if (Msg)
				goto parse_error;
			Msg = hex2bin_m(value, &tmplen);
			if (!Msg)
				goto parse_error;
		} else if (!strcmp(keyword, "Seed")) {
			if (strlen(value) & 1)
				*(--value) = '0';
			if (Seed)
				goto parse_error;
			Seed = hex2bin_m(value, &SeedLen);
			if (!Seed)
				goto parse_error;
		} else if (!strcmp(keyword, "MD"))
			continue;
		else
			goto parse_error;

		fputs(olinebuf, out);

		if (md && Msg && (MsgLen >= 0)) {
			if (!print_dgst(md, out, Msg, MsgLen))
				goto error;
			free(Msg);
			Msg = NULL;
			MsgLen = -1;
			Len = -1;
		} else if (md && Seed && (SeedLen > 0)) {
			if (!print_monte(md, out, Seed, SeedLen))
				goto error;
			free(Seed);
			Seed = NULL;
			SeedLen = -1;
		}

	}

	ret = 1;

 error:

	if (olinebuf)
		free(olinebuf);
	if (linebuf)
		free(linebuf);
	if (Msg)
		free(Msg);
	if (Seed)
		free(Seed);

	return ret;

 parse_error:

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

}

#define MAX_SHA_HASH_SIZE 64
static int print_dgst(gnutls_digest_algorithm_t emd, FILE * out,
		      unsigned char *Msg, int Msglen)
{
	int i, mdlen;
	unsigned char md[MAX_SHA_HASH_SIZE];
	int ret;

	mdlen = gnutls_hmac_get_len(emd);

	ret = gnutls_hash_fast(emd, Msg, Msglen, md);
	if (ret < 0) {
		fprintf(stderr, "Error calculating HASH: %s\n",
			gnutls_strerror(ret));
		return 0;
	}
	fputs("MD = ", out);
	for (i = 0; i < mdlen; i++)
		fprintf(out, "%02x", md[i]);
	fputs("\n", out);
	return 1;
}

static int print_monte(gnutls_digest_algorithm_t md, FILE * out,
		       unsigned char *Seed, int SeedLen)
{
	unsigned int i, j, k;
	int ret = 0, rv = 0;
	gnutls_hash_hd_t ctx;
	unsigned char *m1, *m2, *m3, *p;
	unsigned int mlen, m1len, m2len, m3len;

	ret = gnutls_hash_init(&ctx, md);
	if (ret < 0) {
		do_print_errors();
		exit(1);
	}

	if (SeedLen > MAX_SHA_HASH_SIZE)
		mlen = SeedLen;
	else
		mlen = MAX_SHA_HASH_SIZE;

	m1 = malloc(mlen);
	m2 = malloc(mlen);
	m3 = malloc(mlen);

	if (!m1 || !m2 || !m3)
		goto mc_error;

	m1len = m2len = m3len = SeedLen;
	memcpy(m1, Seed, SeedLen);
	memcpy(m2, Seed, SeedLen);
	memcpy(m3, Seed, SeedLen);

	fputs("\n", out);

	for (j = 0; j < 100; j++) {
		for (i = 0; i < 1000; i++) {
			ret = gnutls_hash(ctx, m1, m1len);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_hash(ctx, m2, m2len);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_hash(ctx, m3, m3len);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			p = m1;
			m1 = m2;
			m1len = m2len;
			m2 = m3;
			m2len = m3len;
			m3 = p;
			gnutls_hash_output(ctx, m3);
			m3len = gnutls_hash_get_len(md);
		}
		fprintf(out, "COUNT = %d\n", j);
		fputs("MD = ", out);
		for (k = 0; k < m3len; k++)
			fprintf(out, "%02x", m3[k]);
		fputs("\n\n", out);
		memcpy(m1, m3, m3len);
		memcpy(m2, m3, m3len);
		m1len = m2len = m3len;
	}

	rv = 1;

 mc_error:
	if (m1)
		free(m1);
	if (m2)
		free(m2);
	if (m3)
		free(m3);

	gnutls_hash_deinit(ctx, NULL);

	return rv;
}
