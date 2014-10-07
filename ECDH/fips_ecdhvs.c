/* fips/ecdh/fips_ecdhvs.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
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

int _gnutls_ecdh_compute_key(gnutls_ecc_curve_t curve,
			   const gnutls_datum_t *x, const gnutls_datum_t *y,
			   const gnutls_datum_t *k,
			   const gnutls_datum_t *peer_x, const gnutls_datum_t *peer_y,
			   gnutls_datum_t *Z);

int _gnutls_ecdh_generate_key(gnutls_ecc_curve_t curve,
			      gnutls_datum_t *x, gnutls_datum_t *y,
			      gnutls_datum_t *k);


static gnutls_digest_algorithm_t parse_md(char *line)
{
	char *p;
	if (line[0] != '[' || line[1] != 'E')
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

static gnutls_ecc_curve_t lookup_curve2(char *cname)
{
	char *p;
	p = strchr(cname, ']');
	if (!p) {
		fprintf(stderr, "Parse error: missing ]\n");
		return GNUTLS_ECC_CURVE_INVALID;
	}
	*p = 0;

	if (!strcmp(cname, "P-192"))
		return GNUTLS_ECC_CURVE_SECP192R1;
	if (!strcmp(cname, "P-224"))
		return GNUTLS_ECC_CURVE_SECP224R1;
	if (!strcmp(cname, "P-256"))
		return GNUTLS_ECC_CURVE_SECP256R1;
	if (!strcmp(cname, "P-384"))
		return GNUTLS_ECC_CURVE_SECP384R1;
	if (!strcmp(cname, "P-521"))
		return GNUTLS_ECC_CURVE_SECP521R1;

	fprintf(stderr, "Unknown Curve name %s\n", cname);
	return GNUTLS_ECC_CURVE_INVALID;
}

static gnutls_ecc_curve_t lookup_curve(char *cname)
{
	char *p;
	p = strchr(cname, ':');
	if (!p) {
		fprintf(stderr, "Parse error: missing :\n");
		return GNUTLS_ECC_CURVE_INVALID;
	}
	cname = p + 1;
	while (isspace(*cname))
		cname++;
	return lookup_curve2(cname);
}

static void ec_output_Zhash(FILE * out, int exout, gnutls_ecc_curve_t group,
			    gnutls_datum_t* ix, gnutls_datum_t* iy, gnutls_datum_t* id,
			    gnutls_datum_t* cx, gnutls_datum_t* cy,
			    gnutls_digest_algorithm_t md,
			    unsigned char *rhash, size_t rhashlen)
{
	gnutls_datum_t Z = {NULL, 0};
	gnutls_datum_t _ix = {NULL, 0}, _iy = {NULL,0}, _id = {NULL,0};
	unsigned char chash[64];
	int ret;

	if (rhash == NULL) {
		if (md)
			rhashlen = gnutls_hash_get_len(md);
		ret = _gnutls_ecdh_generate_key(group, &_ix, &_iy, &_id);
		if (ret < 0) {
			fprintf(stderr, "error in %s:%d\n", __func__, __LINE__);
			exit(1);
		}
		ix = &_ix;
		iy = &_iy;
		id = &_id;

		if (md) {
			OutputValue("QeIUTx", _ix.data, _ix.size, out, 0);
			OutputValue("QeIUTy", _iy.data, _iy.size, out, 0);
			OutputValue("QeIUTd", _id.data, _id.size, out, 0);
		} else {
			OutputValue("QIUTx", _ix.data, _ix.size, out, 0);
			OutputValue("QIUTy", _iy.data, _iy.size, out, 0);
			OutputValue("QIUTd", _id.data, _id.size, out, 0);
		}
	}

	ret = _gnutls_ecdh_compute_key(group, ix, iy, id, cx, cy, &Z);
	if (ret < 0) {
		fprintf(out, "Result = F\n");
		goto fail;
	}
	if (md) {
		if (exout)
			OutputValue("Z", Z.data, Z.size, out, 0);
		gnutls_hash_fast(md, Z.data, Z.size, chash);
		OutputValue(rhash ? "IUTHashZZ" : "HashZZ",
			    chash, rhashlen, out, 0);
		if (rhash) {
			fprintf(out, "Result = %s\n",
				memcmp(chash, rhash, rhashlen) ? "F" : "P");
		}
	} else
		OutputValue("ZIUT", Z.data, Z.size, out, 0);
 fail:
	gnutls_free(Z.data);
	gnutls_free(_ix.data);
	gnutls_free(_iy.data);
	gnutls_free(_id.data);
}

int main(int argc, char **argv)
{
	char **args = argv + 1;
	int argn = argc - 1;
	FILE *in, *out;
	char buf[2048], lbuf[2048];
	unsigned char *rhash = NULL;
	long rhashlen;
	gnutls_datum_t cx = {NULL, 0}, cy = {NULL,0};
	gnutls_datum_t id = {NULL,0}, ix = {NULL,0}, iy = {NULL,0};
	gnutls_digest_algorithm_t md = GNUTLS_DIG_UNKNOWN;
	char *keyword = NULL, *value = NULL;
	int do_verify = -1, exout = 0;
	int rv = 1;
	gnutls_ecc_curve_t nid = GNUTLS_ECC_CURVE_INVALID;

	int param_set = -1;

	if (argn && !strcmp(*args, "ecdhver")) {
		do_verify = 1;
		args++;
		argn--;
	} else if (argn && !strcmp(*args, "ecdhgen")) {
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
			"%s [ecdhver|ecdhgen|] [-exout] (infile outfile)\n",
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
		} else
			out = stdout;
	} else if (argn == 0) {
		in = stdin;
		out = stdout;
	} else {
		fprintf(stderr,
			"%s [ecdhver|ecdhgen|] [-exout] (infile outfile)\n",
			argv[0]);
		exit(1);
	}

	while (fgets(buf, sizeof(buf), in) != NULL) {
		fputs(buf, out);
		if (buf[0] == '[' && buf[1] == 'E') {
			int c = buf[2];
			if (c < 'A' || c > 'E') {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
			param_set = c - 'A';
			/* If just [E?] then initial paramset */
			if (buf[3] == ']')
				continue;
		}
		if (strlen(buf) > 10 && !strncmp(buf, "[Curve", 6)) {
			if (param_set == -1) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
			nid = lookup_curve(buf);
			if (nid == GNUTLS_ECC_CURVE_INVALID) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
		}

		if (strlen(buf) > 4 && buf[0] == '[' && buf[2] == '-') {
			nid = lookup_curve2(buf + 1);
			if (nid == GNUTLS_ECC_CURVE_INVALID) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
		}

		if (strlen(buf) > 6 && !strncmp(buf, "[E", 2)) {
			md = parse_md(buf);
			if (md == GNUTLS_DIG_UNKNOWN) {
				fprintf(stderr, "Parse error: %s:%d: %s\n", __func__, __LINE__, buf);
				goto parse_error;
			}
			continue;
		}
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "QeCAVSx") || !strcmp(keyword, "QCAVSx")) {
			if (!do_hex2raw(&cx, value)) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
		} else if (!strcmp(keyword, "QeCAVSy")
			   || !strcmp(keyword, "QCAVSy")) {
			if (!do_hex2raw(&cy, value)) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}

			if (do_verify == 0)
				ec_output_Zhash(out, exout, nid,
						NULL, NULL, NULL,
						&cx, &cy, md, rhash, rhashlen);
		} else if (!strcmp(keyword, "deIUT")) {
			if (!do_hex2raw(&id, value)) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
		} else if (!strcmp(keyword, "QeIUTx")) {
			if (!do_hex2raw(&ix, value)) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
		} else if (!strcmp(keyword, "QeIUTy")) {
			if (!do_hex2raw(&iy, value)) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
		} else if (!strcmp(keyword, "CAVSHashZZ")) {
			if (!md) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
			rhash = hex2bin_m(value, &rhashlen);
			if (!rhash || rhashlen != gnutls_hash_get_len(md)) {
				fprintf(stderr, "Parse error: %s:%d\n", __func__, __LINE__);
				goto parse_error;
			}
			ec_output_Zhash(out, exout, nid, &ix, &iy, &id, &cx, &cy,
					md, rhash, rhashlen);
		}
	}
	rv = 0;
 parse_error:
	if (id.data)
		gnutls_free(id.data);
	if (ix.data)
		gnutls_free(ix.data);
	if (iy.data)
		gnutls_free(iy.data);
	if (cx.data)
		gnutls_free(cx.data);
	if (cy.data)
		gnutls_free(cy.data);
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
	if (rv)
		fprintf(stderr, "Error Parsing request file\n");
	return rv;
}
