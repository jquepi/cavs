/* fips/aes/fips_gcmtest.c */
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

#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

static char buf[204800];
static char lbuf[204800];

static void gcmtest(FILE * in, FILE * out, int encrypt)
{
	char *keyword, *value;
	int keylen = -1, ivlen = -1, aadlen = -1, taglen = -1, ptlen = -1;
	int ret;
	long l;
	unsigned line = 0;
	gnutls_datum_t div;
	gnutls_datum_t dkey;
	unsigned char *key = NULL, *iv = NULL, *aad = NULL, *tag = NULL;
	unsigned char *ct = NULL, *pt = NULL;
	gnutls_cipher_hd_t ctx = NULL;
	gnutls_cipher_algorithm_t gcm;

	while (fgets(buf, sizeof buf, in) != NULL) {
		line++;
		fputs(buf, out);
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if (!strcmp(keyword, "[Keylen")) {
			keylen = atoi(value);
			if (keylen == 128)
				gcm = GNUTLS_CIPHER_AES_128_GCM;
			else if (keylen == 256)
				gcm = GNUTLS_CIPHER_AES_256_GCM;
			else {
				fprintf(stderr, "Unsupported keylen %d\n",
					keylen);
			}
			keylen >>= 3;
		} else if (!strcmp(keyword, "[IVlen"))
			ivlen = atoi(value) >> 3;
		else if (!strcmp(keyword, "[AADlen"))
			aadlen = atoi(value) >> 3;
		else if (!strcmp(keyword, "[Taglen"))
			taglen = atoi(value) >> 3;
		else if (!strcmp(keyword, "[PTlen"))
			ptlen = atoi(value) >> 3;
		else if (!strcmp(keyword, "Key")) {
			key = hex2bin_m(value, &l);
			if (l != keylen) {
				fprintf(stderr, "Inconsistent Key length\n");
				exit(1);
			}
		} else if (!strcmp(keyword, "IV")) {
			iv = hex2bin_m(value, &l);
			if (l != ivlen) {
				fprintf(stderr, "Inconsistent IV length\n");
				exit(1);
			}
		} else if (!strcmp(keyword, "PT")) {
			pt = hex2bin_m(value, &l);
			if (l != ptlen) {
				fprintf(stderr, "Inconsistent PT length\n");
				exit(1);
			}
		} else if (!strcmp(keyword, "CT")) {
			ct = hex2bin_m(value, &l);
			if (l != ptlen) {
				fprintf(stderr, "Inconsistent CT length\n");
				exit(1);
			}
		} else if (!strcmp(keyword, "AAD")) {
			aad = hex2bin_m(value, &l);
			if (l != aadlen) {
				fprintf(stderr, "Inconsistent AAD length\n");
				exit(1);
			}
		} else if (!strcmp(keyword, "Tag")) {
			tag = hex2bin_m(value, &l);
			if (l != taglen) {
				fprintf(stderr, "Inconsistent Tag length\n");
				exit(1);
			}
		}

		if (encrypt && pt && aad && (iv || encrypt == 1)) {

			if (!iv) {
				fprintf(stderr, "No IV: %d\n", line);
				exit(1);
			}

			tag = malloc(taglen);

			div.size = ivlen;
			div.data = iv;

			dkey.data = key;
			dkey.size = keylen;

			if (ctx != NULL)
				gnutls_cipher_deinit(ctx);

			ret = gnutls_cipher_init(&ctx, gcm, &dkey, &div);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			OutputValue("IV", iv, ivlen, out, 0);

			if (aadlen) {
				ret = gnutls_cipher_add_auth(ctx, aad, aadlen);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}
			}
			if (ptlen) {
				ct = malloc(ptlen);

				ret =
				    gnutls_cipher_encrypt2(ctx, pt, ptlen, ct,
							   ptlen);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}
			}
			ret = gnutls_cipher_tag(ctx, tag, taglen);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			OutputValue("CT", ct, ptlen, out, 0);
			OutputValue("Tag", tag, taglen, out, 0);
			if (iv)
				free(iv);
			if (aad)
				free(aad);
			if (ct)
				free(ct);
			if (pt)
				free(pt);
			if (key)
				free(key);
			if (tag)
				free(tag);
			iv = aad = ct = pt = key = tag = NULL;
		}
		if (!encrypt && tag) {

			if (!iv || ivlen == 0) {
				fprintf(stderr, "No IV: %d\n", line);
				exit(1);
			}

			if (!key || keylen == 0) {
				fprintf(stderr, "No key: %d\n", line);
				exit(1);
			}

			/* Relax FIPS constraints for testing */
			div.size = ivlen;
			div.data = iv;

			dkey.data = key;
			dkey.size = keylen;

			if (ctx != NULL)
				gnutls_cipher_deinit(ctx);

			ret = gnutls_cipher_init(&ctx, gcm, &dkey, &div);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			if (aadlen) {
				ret = gnutls_cipher_add_auth(ctx, aad, aadlen);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}
			}
			if (ptlen) {
				pt = malloc(ptlen);
				if (!ct) {
					fprintf(stderr, "No ciphertext: %d\n",
						line);
					exit(1);
				}

				if (!pt) {
					fprintf(stderr, "No plaintext: %d\n",
						line);
					exit(1);
				}

				ret =
				    gnutls_cipher_decrypt2(ctx, ct, ptlen, pt,
							   ptlen);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}
			}

			ret = gnutls_cipher_tag(ctx, tag, taglen);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			if (ret < 0)
				fprintf(out, "FAIL\n");
			else
				OutputValue("PT", pt, ptlen, out, 0);
			if (iv)
				free(iv);
			if (aad)
				free(aad);
			if (ct)
				free(ct);
			if (pt)
				free(pt);
			if (key)
				free(key);
			if (tag)
				free(tag);
			iv = aad = ct = pt = key = tag = NULL;
		}
	}
	if (ctx != NULL)
		gnutls_cipher_deinit(ctx);
}

int main(int argc, char **argv)
{
	int encrypt;
	int xts = 0, ccm = 0;
	FILE *in, *out;
	if (argc == 4) {
		in = fopen(argv[2], "r");
		if (!in) {
			fprintf(stderr, "Error opening input file\n");
			exit(1);
		}
		out = fopen(argv[3], "w");
		if (!out) {
			fprintf(stderr, "Error opening output file\n");
			exit(1);
		}
	} else if (argc == 2) {
		in = stdin;
		out = stdout;
	} else {
		fprintf(stderr, "%s [-encrypt|-decrypt]\n", argv[0]);
		exit(1);
	}

	if (!strcmp(argv[1], "-encrypt"))
		encrypt = 1;
	else if (!strcmp(argv[1], "-encryptIVext"))
		encrypt = 2;
	else if (!strcmp(argv[1], "-decrypt"))
		encrypt = 0;
	else {
		fprintf(stderr, "Don't know how to %s.\n", argv[1]);
		exit(1);
	}

	gcmtest(in, out, encrypt);

	if (argc == 4) {
		fclose(in);
		fclose(out);
	}

	return 0;
}
