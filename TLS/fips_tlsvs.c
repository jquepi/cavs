/* fips_tlsvs.c */
/* Written by Tomas Mraz using parts of code from the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2013, 2014 Red Hat, Inc.
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 */

#include <gnutls/gnutls.h>

#include "fips_utl.h"

int
_gnutls_prf_raw(gnutls_mac_algorithm_t mac,
		size_t master_size, const void *master,
		size_t label_size, const char *label,
		size_t seed_size, const char *seed, size_t outsize,
                char *out);

/* Bits for algorithm2 (handshake digests and other extra flags) */

#define SSL_HANDSHAKE_MAC_MD5 0x10
#define SSL_HANDSHAKE_MAC_SHA 0x20
#define SSL_HANDSHAKE_MAC_GOST94 0x40
#define SSL_HANDSHAKE_MAC_SHA256 0x80
#define SSL_HANDSHAKE_MAC_SHA384 0x100
#define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)

#define TLS1_PRF_SHA256 GNUTLS_MAC_SHA256
#define TLS1_PRF_SHA384 GNUTLS_MAC_SHA384
#define TLS1_PRF_SHA512 GNUTLS_MAC_SHA512
#define TLS1_PRF GNUTLS_MAC_UNKNOWN

#define TLS_MD_MASTER_SECRET_CONST              "master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE         (sizeof(TLS_MD_MASTER_SECRET_CONST)-1)
#define TLS_MD_KEY_EXPANSION_CONST              "key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE         (sizeof(TLS_MD_KEY_EXPANSION_CONST)-1)

#define TLS_MASTER_SECRET_LEN 384/8

static int parse_md(const char *str)
{
	const char *bits;

	bits = strstr(str, "SHA-");
	if (bits == NULL)
		return TLS1_PRF;

	switch (atoi(bits + 4)) {
	case 256:
		return TLS1_PRF_SHA256;

	case 384:
		return TLS1_PRF_SHA384;
	case 512:
		return TLS1_PRF_SHA512;
	}

	return -1;
}

int main(int argc, char **argv)
{
	FILE *in = NULL, *out = NULL;
	long algmask = 0;
	char buf[2048], lbuf[2048];
	char *keyword, *value;
	unsigned char *pms = NULL, *shrandom = NULL;
	unsigned char *chrandom = NULL, *srandom = NULL, *crandom = NULL;
	long pmslen, shrandomlen, chrandomlen, srandomlen, crandomlen;
	int kblen = 0, parsed = 0;

	if (argc == 3) {
		in = fopen(argv[1], "r");
		if (!in) {
			fprintf(stderr, "Error opening input file\n");
			exit(1);
		}
		out = fopen(argv[2], "w");
		if (!out) {
			fprintf(stderr, "Error opening output file\n");
			exit(1);
		}
	} else if (argc == 1) {
		in = stdin;
		out = stdout;
	} else {
		fprintf(stderr, "%s [infile outfile]\n", argv[0]);
		exit(1);
	}

	while (fgets(buf, sizeof(buf), in) != NULL) {
		fputs(buf, out);
		if (strncmp(buf, "[TLS", 4) == 0) {
			algmask = parse_md(buf);
			if (algmask == -1) {
				fprintf(stderr,
					"malformed or unsupported hash algorithm\n");
				exit(1);
			}
			parsed = 0;
			continue;
		}

		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;

		if (!strcmp(keyword, "[pre-master secret length")) {
			if (strcmp(value, "384]")) {
				fprintf(stderr,
					"unsupported pre-master secret length\n");
				exit(1);
			}
		}

		if (!strcmp(keyword, "[key block length")) {
			int vlen = strlen(value);
			if (value[vlen - 1] == ']')
				value[vlen - 1] = '\0';

			if ((kblen = atoi(value)) == 0) {
				fprintf(stderr, "malformed key block length\n");
				exit(1);
			}
			kblen /= 8;	/* bytes */
		}

		if (!strcmp(keyword, "pre_master_secret")) {
			pms = hex2bin_m(value, &pmslen);
			parsed |= 0x1;
		}

		if (!strcmp(keyword, "serverHello_random")) {
			shrandom = hex2bin_m(value, &shrandomlen);
			parsed |= 0x2;
		}

		if (!strcmp(keyword, "clientHello_random")) {
			chrandom = hex2bin_m(value, &chrandomlen);
			parsed |= 0x4;
		}

		if (!strcmp(keyword, "server_random")) {
			srandom = hex2bin_m(value, &srandomlen);
			parsed |= 0x8;
		}

		if (!strcmp(keyword, "client_random")) {
			crandom = hex2bin_m(value, &crandomlen);
			parsed |= 0x10;
		}

		if (parsed == 0x1F) {
			int buflen =
			    kblen <
			    TLS_MASTER_SECRET_LEN ? TLS_MASTER_SECRET_LEN :
			    kblen;
			unsigned char *msbuf = calloc(1, TLS_MASTER_SECRET_LEN);
			unsigned char *seed = calloc(1, shrandomlen+chrandomlen);
			unsigned char *outbuf = calloc(1, buflen);

			memcpy(seed, chrandom, chrandomlen);
			memcpy(seed+chrandomlen, shrandom, shrandomlen);

			_gnutls_prf_raw(algmask,
					 pmslen, pms,
					 TLS_MD_MASTER_SECRET_CONST_SIZE,
					 TLS_MD_MASTER_SECRET_CONST,
					 shrandomlen+chrandomlen, seed,
					 TLS_MASTER_SECRET_LEN, msbuf);

			OutputValue("master_secret", msbuf,
				    TLS_MASTER_SECRET_LEN, out, 0);

			memcpy(seed, srandom, srandomlen);
			memcpy(seed+srandomlen, crandom, crandomlen);

			_gnutls_prf_raw(algmask,
					 TLS_MASTER_SECRET_LEN, msbuf,
					 TLS_MD_KEY_EXPANSION_CONST_SIZE,
					 TLS_MD_KEY_EXPANSION_CONST,
					 srandomlen+crandomlen, seed,
					 kblen, outbuf);

			OutputValue("key_block", outbuf, kblen, out, 0);

			parsed = 0;
			free(msbuf);
			free(seed);
			free(outbuf);
		}

	}
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
	return 0;
}

