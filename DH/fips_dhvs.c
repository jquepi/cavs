/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 * Copyright (c) 2014 Red Hat, Inc.
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
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gmp.h>
#include <nettle/dsa.h>
#include <nettle/asn1.h>
#include <nettle/bignum.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

int _gnutls_dh_generate_key(gnutls_dh_params_t dh_params,
                            gnutls_datum_t *priv_key, gnutls_datum_t *pub_key);
int _gnutls_dh_compute_key(gnutls_dh_params_t dh_params,
                           const gnutls_datum_t *priv_key, const gnutls_datum_t *pub_key,
                           const gnutls_datum_t *peer_key, gnutls_datum_t *Z);

static gnutls_digest_algorithm_t parse_md(char *line)
{
	char *p;
	if (line[0] != '[' || line[1] != 'F')
		return GNUTLS_DIG_UNKNOWN;
	p = strchr(line, '-');
	if (!p)
		return GNUTLS_DIG_UNKNOWN;
	line = p + 1;
	p = strchr(line, ']');
	if (!p)
		return GNUTLS_DIG_UNKNOWN;
	*p = 0;
	p = line;
	while (isspace(*p))
		p++;
	if (!strcmp(p, "SHA1"))
		return GNUTLS_DIG_SHA1;
	else if (!strcmp(p, "SHA224"))
		return GNUTLS_DIG_SHA224;
	else if (!strcmp(p, "SHA256"))
		return GNUTLS_DIG_SHA256;
	else if (!strcmp(p, "SHA384"))
		return GNUTLS_DIG_SHA384;
	else if (!strcmp(p, "SHA512"))
		return GNUTLS_DIG_SHA512;
	else
		return GNUTLS_DIG_UNKNOWN;
}

static void output_Zhash(FILE * out, int exout,
			 gnutls_dh_params_t dh_params,
			 gnutls_datum_t *priv_key, gnutls_datum_t *pub_key,
			 gnutls_datum_t* peerkey, gnutls_digest_algorithm_t md,
			 unsigned char *rhash, size_t rhashlen)
{
	gnutls_datum_t Z;
	unsigned char chash[64];
	int ret;
	if (rhash == NULL) {
		rhashlen = gnutls_hash_get_len(md);
		if (_gnutls_dh_generate_key(dh_params, priv_key, pub_key) < 0) {
			fprintf(stderr, "error in %s:%d\n", __func__, __LINE__);
			exit(1);
		}
		do_bn_print_name(out, "XephemIUT", priv_key);
		do_bn_print_name(out, "YephemIUT", pub_key);
	}
	ret = _gnutls_dh_compute_key(dh_params, priv_key, pub_key, peerkey, &Z);
	if (ret < 0) {
		fprintf(stderr, "error in %s:%d\n", __func__, __LINE__);
		exit(1);
	}
	if (exout)
		OutputValue("Z", Z.data, Z.size, out, 0);
	gnutls_hash_fast(md, Z.data, Z.size, chash);
	OutputValue(rhash ? "IUTHashZZ" : "HashZZ", chash, rhashlen, out,
		    0);
	if (rhash) {
		fprintf(out, "Result = %s\n",
			memcmp(chash, rhash, rhashlen) ? "F" : "P");
	} else {
		gnutls_free(priv_key->data);
		priv_key->data = NULL;
		gnutls_free(pub_key->data);
		pub_key->data = NULL;
	}
	gnutls_free(Z.data);
}

int main(int argc, char **argv)
{
	char **args = argv + 1;
	int argn = argc - 1;
	FILE *in, *out;
	char buf[2048], lbuf[2048];
	unsigned char *rhash;
	long rhashlen;
	gnutls_digest_algorithm_t md = GNUTLS_DIG_UNKNOWN;
	gnutls_datum_t peerkey = {NULL, 0};
	gnutls_datum_t p = {NULL, 0};
	gnutls_datum_t q = {NULL, 0};
	gnutls_datum_t g = {NULL, 0};
	gnutls_datum_t pub_key = {NULL, 0};
	gnutls_datum_t priv_key = {NULL, 0};
	char *keyword = NULL, *value = NULL;
	int do_verify = -1, exout = 0, ret;
	gnutls_dh_params_t dh_params = NULL;

	if (argn && !strcmp(*args, "dhver")) {
		do_verify = 1;
		args++;
		argn--;
	} else if (argn && !strcmp(*args, "dhgen")) {
		do_verify = 0;
		args++;
		argn--;
	}

	if (argn && !strcmp(*args, "-exout")) {
		exout = 1;
		args++;
		argn--;
	}


	if (do_verify == -1) {
		fprintf(stderr,
			"%s [dhver|dhgen|] [-exout] (infile outfile)\n",
			argv[0]);
		exit(1);
	}

	if (argn == 2 || argn == 1) {
		in = fopen(*args, "r");
		if (!in) {
			fprintf(stderr, "Error opening input file\n");
			exit(1);
		}
		if (argn == 2) {
			out = fopen(args[1], "w");
			if (!out) {
				fprintf(stderr, "Error opening output file\n");
				exit(1);
			}
		} else {
			out = stdout;
		}
	} else if (argn == 0) {
		in = stdin;
		out = stdout;
	} else {
		fprintf(stderr,
			"%s [dhver|dhgen|] [-exout] (infile outfile)\n",
			argv[0]);
		exit(1);
	}

	while (fgets(buf, sizeof(buf), in) != NULL) {
		fputs(buf, out);
		if (strlen(buf) > 6 && !strncmp(buf, "[F", 2)) {
			md = parse_md(buf);
			if (md == GNUTLS_DIG_UNKNOWN)
				goto parse_error;
			if (p.data) {
				gnutls_free(p.data);
				p.data = NULL;
			}
			if (q.data) {
				gnutls_free(q.data);
				q.data = NULL;
			}
			if (g.data) {
				gnutls_free(g.data);
				g.data = NULL;
			}
			if (priv_key.data) {
				gnutls_free(priv_key.data);
				priv_key.data = NULL;
			}
			if (pub_key.data) {
				gnutls_free(pub_key.data);
				pub_key.data = NULL;
			}
			if (dh_params != NULL) {
				gnutls_dh_params_deinit(dh_params);
				dh_params = NULL;
			}
			continue;
		}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "P")) {
			if (!do_hex2raw(&p, value))
				goto parse_error;
		} else if (!strcmp(keyword, "Q")) {
			if (!do_hex2raw(&q, value))
				goto parse_error;
		} else if (!strcmp(keyword, "G")) {
			if (!do_hex2raw(&g, value))
				goto parse_error;
			ret = gnutls_dh_params_init(&dh_params);
			if (ret < 0)
				exit(1);
			ret = gnutls_dh_params_import_raw(dh_params, &p, &g);
			if (ret < 0) {
				fprintf(stderr, "error importing DH params\n");
				exit(1);
			}
		} else if (!strcmp(keyword, "XephemIUT")) {
			if (!do_hex2raw(&priv_key, value))
				goto parse_error;
		} else if (!strcmp(keyword, "YephemIUT")) {
			if (!do_hex2raw(&pub_key, value))
				goto parse_error;
		} else if (!strcmp(keyword, "YephemCAVS")) {
			if (!do_hex2raw(&peerkey, value))
				goto parse_error;
			if (do_verify == 0) {
				output_Zhash(out, exout, dh_params, &priv_key, &pub_key,
				             &peerkey, md, NULL, 0);
			}
		} else if (!strcmp(keyword, "CAVSHashZZ")) {
			if (md == GNUTLS_DIG_UNKNOWN)
				goto parse_error;
			rhash = hex2bin_m(value, &rhashlen);
			if (!rhash || rhashlen != gnutls_hash_get_len(md))
				goto parse_error;

			output_Zhash(out, exout, dh_params, &priv_key, &pub_key, &peerkey, md,
				     rhash, rhashlen);
		}
	}
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
	return 0;
      parse_error:
	fprintf(stderr, "Error Parsing request file\n");
	return 1;
}
