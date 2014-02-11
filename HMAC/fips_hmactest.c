/* fips_hmactest.c */
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

static int hmac_test(gnutls_mac_algorithm_t md, FILE * out, FILE * in);
static int print_hmac(gnutls_mac_algorithm_t md, FILE * out,
		      unsigned char *Key, int Klen,
		      unsigned char *Msg, int Msglen, int Tlen);

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

	if (!hmac_test(GNUTLS_MAC_SHA1, out, in)) {
		fprintf(stderr, "FATAL hmac file processing error\n");
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

#define HMAC_TEST_MAXLINELEN	1024

int hmac_test(gnutls_mac_algorithm_t md, FILE * out, FILE * in)
{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	unsigned char *Key = NULL, *Msg = NULL;
	int Count, Klen, Tlen;
	long Keylen, Msglen;
	int ret = 0;
	int lnum = 0;

	olinebuf = malloc(HMAC_TEST_MAXLINELEN);
	linebuf = malloc(HMAC_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	Count = -1;
	Klen = -1;
	Tlen = -1;

	while (fgets(olinebuf, HMAC_TEST_MAXLINELEN, in)) {
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
			if (fputs(olinebuf, out) < 0)
				goto error;
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
		} else if (!strcmp(keyword, "Count")) {
			if (Count != -1)
				goto parse_error;
			Count = atoi(value);
			if (Count < 0)
				goto parse_error;
		} else if (!strcmp(keyword, "Klen")) {
			if (Klen != -1)
				goto parse_error;
			Klen = atoi(value);
			if (Klen < 0)
				goto parse_error;
		} else if (!strcmp(keyword, "Tlen")) {
			if (Tlen != -1)
				goto parse_error;
			Tlen = atoi(value);
			if (Tlen < 0)
				goto parse_error;
		} else if (!strcmp(keyword, "Msg")) {
			if (Msg)
				goto parse_error;
			Msg = hex2bin_m(value, &Msglen);
			if (!Msg)
				goto parse_error;
		} else if (!strcmp(keyword, "Key")) {
			if (Key)
				goto parse_error;
			Key = hex2bin_m(value, &Keylen);
			if (!Key)
				goto parse_error;
		} else if (!strcmp(keyword, "Mac"))
			continue;
		else
			goto parse_error;

		fputs(olinebuf, out);

		if (Key && Msg && (Tlen > 0) && (Klen > 0)) {
			if (!print_hmac(md, out, Key, Klen, Msg, Msglen, Tlen))
				goto error;
			free(Key);
			Key = NULL;
			free(Msg);
			Msg = NULL;
			Klen = -1;
			Tlen = -1;
			Count = -1;
		}

	}

	ret = 1;

 error:

	if (olinebuf)
		free(olinebuf);
	if (linebuf)
		free(linebuf);
	if (Key)
		free(Key);
	if (Msg)
		free(Msg);

	return ret;

 parse_error:

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

}

#define MAX_SHA_HASH_SIZE 64
static int print_hmac(gnutls_mac_algorithm_t algo, FILE * out,
		      unsigned char *Key, int Klen,
		      unsigned char *Msg, int Msglen, int Tlen)
{
	int i, mdlen;
	unsigned char md[MAX_SHA_HASH_SIZE];
	int ret;

	mdlen = gnutls_hmac_get_len(algo);
	if (Tlen > mdlen) {
		fputs("Parameter error, Tlen > HMAC length\n", stderr);
		return 0;
	}

	ret = gnutls_hmac_fast(algo, Key, Klen, Msg, Msglen, md);
	if (ret < 0) {
		fprintf(stderr, "Error calculating HMAC: %s\n",
			gnutls_strerror(ret));
		return 0;
	}
	fputs("Mac = ", out);
	for (i = 0; i < Tlen; i++)
		fprintf(out, "%02x", md[i]);
	fputs("\n", out);
	return 1;
}
