/*
 * Copyright (c) 2014, Red Hat, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gmp.h>
#include <nettle/bignum.h>
#include <nettle/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"
#include "rsa-fips.h"

static void pbn(const char *name, mpz_t n, unsigned wanted_size)
{
unsigned size16 = mpz_sizeinbase(n, 16);
unsigned bytes = mpz_sizeinbase(n, 256);
unsigned i;

	printf("%s = ", name);
	if (bytes < wanted_size) {
		for (i=0;i<wanted_size-bytes;i++)
			printf("00");
	}

	if (size16 % 2 == 0)
		gmp_printf("%Zx\n", n);
	else
		gmp_printf("0%Zx\n", n);
	return;
}

static void pbn1(const char *name, mpz_t n)
{
unsigned size16 = mpz_sizeinbase(n, 16);

	if (size16 % 2 == 0)
		gmp_printf("%s = %Zx\n", name, n);
	else
		gmp_printf("%s = 0%Zx\n", name, n);
	return;
}

static int compare(gnutls_datum_t *_d1, gnutls_datum_t *_d2)
{
	gnutls_datum_t d1, d2;

	memcpy(&d1, _d1, sizeof(d1));
	memcpy(&d2, _d2, sizeof(d2));

	while(d1.size > 0 && d1.data[0] == 0) {
		d1.size--;
		d1.data++;
	}
	while(d2.size > 0 && d2.data[0] == 0) {
		d2.size--;
		d2.data++;
	}

	if (d1.size != d2.size)
		return -1;
	if (memcmp(d1.data, d2.data, d2.size) != 0)
		return -1;
	return 0;
}

static
gnutls_datum_t get_mpi(mpz_t n)
{
	gnutls_datum_t r = {NULL, 0};

	r.size = nettle_mpz_sizeinbase_256_u(n);
	if (r.size == 0)
		return r;

	r.data = malloc(r.size);
	if (r.data == NULL)
		abort();

	nettle_mpz_get_str_256(r.size, r.data, n);
	return r;
}

#define METHOD "[PrimeMethod"

void keygen()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, ret;
	unsigned start = 0;
	struct rsa_public_key pub;
	gnutls_datum_t seed = {NULL, 0};
	struct rsa_private_key priv;
	unsigned int iters = 0, i;
	char s[64];

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[mod", 3)) {
			l = atoi(value);
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, METHOD, sizeof(METHOD) - 1)) {
			if (strncmp(value, "ProvRP", 6) != 0) {
				fprintf(stderr, "unsupported method: %s\n",
					value);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[hash", sizeof("[hash") - 1)) {
			if (strncmp(value, "SHA384", 6) != 0) {
				fprintf(stderr, "unsupported hash: %s\n",
					value);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		}

		if (!strcmp(keyword, "n")) {
			iters = atoi(value);
			if (iters == 0) {
				fprintf(stderr, "error in %s\n", buf);
				exit(1);
			}
			start = 1;
		}

		if (start != 0) {
			start = 0;

			for (i=0;i<iters;i++) {
				if (l == 2048) {
					seed.size = 14*2;
				} else {
					seed.size = 16*2;
				}

				gnutls_rnd(GNUTLS_RND_NONCE, s, seed.size);
				seed.data = (void*)s;

				rsa_public_key_init(&pub);
				rsa_private_key_init(&priv);

				/* set e */
				/*nettle_mpz_set_str_256_u(pub.e, e.size, e.data);*/
				mpz_set_ui(pub.e, 65537);
				pbn("e", pub.e, l/8);
				do_print_name(stdout, "seed", &seed);

				ret = _rsa_generate_fips186_4_keypair(&pub, &priv,
								      seed.size,
								      seed.data, NULL,
								      NULL, l);
				if (ret == 0) {
					do_print_errors();
					exit(1);
				}

				pbn1("p", priv.p);
				pbn1("q", priv.q);
				pbn("n", pub.n, l/8);
				pbn("d", priv.d, l/8);
				putc('\n', stdout);
				fflush(stdout);
				rsa_private_key_clear(&priv);
				rsa_public_key_clear(&pub);
			}
		}
	}
}

void keygen_seed()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, ret;
	unsigned start = 0;
	struct rsa_public_key pub;
	gnutls_datum_t seed = {NULL, 0};
	gnutls_datum_t e = {NULL, 0};
	struct rsa_private_key priv;
	unsigned lineno = 0;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		lineno++;
		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[mod", 3)) {
			l = atoi(value);
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, METHOD, sizeof(METHOD) - 1)) {
			if (strncmp(value, "ProvRP", 6) != 0) {
				fprintf(stderr, "unsupported method: %s\n",
					value);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[hash", sizeof("[hash") - 1)) {
			if (strncmp(value, "SHA384", 6) != 0) {
				fprintf(stderr, "unsupported hash: %s\n",
					value);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		}

		if (!strcmp(keyword, "seed")) {
			free(seed.data);
			seed = hex2raw(value);
			fputs(buf, stdout);
			start = 1;
		} else if (!strcmp(keyword, "e")) {
			free(e.data);
			e = hex2raw(value);
			fputs(buf, stdout);
		}

		if (start != 0) {
			start = 0;

			if (l == 2048) {
				if (seed.size != 14*2) {
					fprintf(stderr, "wrong seed size: %d!\n", seed.size);
					abort();
				}
			} else {
				if (seed.size != 16*2) {
					fprintf(stderr, "wrong seed size: %d!\n", seed.size);
					abort();
				}
			}

			rsa_public_key_init(&pub);
			rsa_private_key_init(&priv);

			/* set e */
			nettle_mpz_set_str_256_u(pub.e, e.size, e.data);

			ret = _rsa_generate_fips186_4_keypair(&pub, &priv,
							      seed.size,
							      seed.data, NULL,
							      NULL, l);
			if (ret == 0) {
				fprintf(stderr, "line: %d\n", lineno);
				do_print_errors();
				exit(1);
			}

			pbn1("p", priv.p);
			pbn1("q", priv.q);
			pbn("n", pub.n, l/8);
			pbn("d", priv.d, l/8);
			putc('\n', stdout);
			fflush(stdout);
			rsa_private_key_clear(&priv);
			rsa_public_key_clear(&pub);
		}
	}
}

void keyver()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, ret;
	gnutls_datum_t e = { NULL, 0 };
	gnutls_datum_t seed = { NULL, 0 }, p = {
	NULL, 0};
	gnutls_datum_t q = { NULL, 0 }, n = {
	NULL, 0};
	gnutls_datum_t d = { NULL, 0 };
	unsigned start = 0;
	unsigned err, exitno = 0;
	struct rsa_public_key pub;
	struct rsa_private_key priv;
	gnutls_datum_t t;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[mod", 3)) {
			l = atoi(value);
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, METHOD, sizeof(METHOD) - 1)) {
			if (strncmp(value, "ProvRP", 6) != 0) {
				fprintf(stderr, "unsupported method: %s\n",
					value);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[hash", sizeof("[hash") - 1)) {
			if (strncmp(value, "SHA384", 6) != 0) {
				fprintf(stderr, "unsupported hash: %s\n",
					value);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		}

		if (!strcmp(keyword, "p")) {
			free(p.data);
			p = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "q")) {
			free(q.data);
			q = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "e")) {
			free(e.data);
			e = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "n")) {
			free(n.data);
			n = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "seed")) {
			free(seed.data);
			seed = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "d")) {
			free(d.data);
			d = hex2raw(value);
			fputs(buf, stdout);
			start = 1;
		}

		if (start != 0) {
			start = 0;

			if (l == 2048) {
				if (seed.size != 14*2) {
					fprintf(stderr, "error in sid.size (have %d, expected: %d)\n", seed.size, 14*2);
					exit(1);
				}
			} else {
				if (seed.size != 16*2) {
					fprintf(stderr, "error in sid.size (have %d, expected: %d)\n", seed.size, 16*2);
					exit(1);
				}
			}

			rsa_public_key_init(&pub);
			rsa_private_key_init(&priv);

			/* set e */
			nettle_mpz_set_str_256_u(pub.e, e.size, e.data);

			ret = _rsa_generate_fips186_4_keypair(&pub, &priv,
							      seed.size,
							      seed.data, NULL,
							      NULL, l);
			if (ret == 0) {
				fprintf(stdout, "FAIL (cannot generate)\n");
				goto cont;
			}

			err = 0;
			t = get_mpi(priv.p);
			if (compare(&t, &p) != 0) {
				fprintf(stderr, "error comparing p\n");
				pbn("expecting p", priv.p, l/8);
				err = 1;
			}
			free(t.data);

			t = get_mpi(priv.q);
			if (compare(&t, &q) != 0) {
				fprintf(stderr, "error comparing q\n");
				pbn("expecting q", priv.q, l/8);
				err = 1;
			}
			free(t.data);

			t = get_mpi(pub.n);
			if (compare(&t, &n) != 0) {
				fprintf(stderr, "error comparing n\n");
				pbn("expecting n", pub.n, l/8);
				err = 1;
			}
			free(t.data);

			t = get_mpi(priv.d);
			if (compare(&t, &d) != 0) {
				fprintf(stderr, "error comparing d\n");
				pbn("expecting d", priv.d, l/8);
				err = 1;
			}
			free(t.data);

			if (err == 0)
				fprintf(stdout, "PASS\n");
			else {
				fprintf(stdout, "FAIL\n");
				exitno = 1;
			}
 cont:
			fflush(stdout);
			rsa_private_key_clear(&priv);
			rsa_public_key_clear(&pub);
		}
	}
	exit(exitno);
}

void sigver()
{
	gnutls_pubkey_t key;
	char buf[1024];
	char lbuf[1024];
	int l = 0;
	char *keyword, *value;
	int ret;
	gnutls_datum_t e = { NULL, 0 }, n = {
	NULL, 0};
	gnutls_datum_t msg = { NULL, 0 };
	gnutls_datum_t sig;
	unsigned sig_algo = 0;

	while (fgets(buf, sizeof buf, stdin) != NULL) {

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[mod", 4)) {
			l = atoi(value);
			if (l == 0) {
				fprintf(stderr, "Error reading modulus: %s\n",
					buf);
				exit(1);
			}

			fputs(buf, stdout);
			fputs("\n", stdout);

			continue;
		}

		if (!strcmp(keyword, "Msg")) {
			msg = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "SHAAlg")) {
			if (strcmp(value, "SHA1") == 0) {
				sig_algo = GNUTLS_SIGN_RSA_SHA1;
			} else if (strcmp(value, "SHA256") == 0) {
				sig_algo = GNUTLS_SIGN_RSA_SHA256;
			} else if (strcmp(value, "SHA224") == 0) {
				sig_algo = GNUTLS_SIGN_RSA_SHA224;
			} else if (strcmp(value, "SHA384") == 0) {
				sig_algo = GNUTLS_SIGN_RSA_SHA384;
			} else if (strcmp(value, "SHA512") == 0) {
				sig_algo = GNUTLS_SIGN_RSA_SHA512;
			} else {
				fprintf(stderr, "unknown hash: %s\n", value);
				exit(1);
			}

			fputs(buf, stdout);
		} else if (!strcmp(keyword, "e")) {
			gnutls_free(e.data);
			e = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "n")) {
			gnutls_free(n.data);
			n = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "S")) {
			sig = hex2raw(value);
			fputs(buf, stdout);

			ret = gnutls_pubkey_init(&key);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_pubkey_import_rsa_raw(key, &n, &e);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret =
			    gnutls_pubkey_verify_data2(key, sig_algo, 0, &msg,
						       &sig);
			if (ret < 0) {
				printf("Result = F\n");
			} else {
				printf("Result = P\n");
			}
			putc('\n', stdout);

			gnutls_free(sig.data);

			gnutls_pubkey_deinit(key);
			sig_algo = 0;
		}
	}
}

void siggen()
{
	gnutls_privkey_t key = NULL;
	char buf[1024];
	char lbuf[1024];
	int l = 0;
	char *keyword, *value;
	int ret;
	gnutls_datum_t n = { NULL, 0 };
	gnutls_datum_t e = { NULL, 0 }, d = {
	NULL, 0};
	gnutls_datum_t msg = { NULL, 0 };
	gnutls_datum_t sig;
	unsigned hash = 0;

	while (fgets(buf, sizeof buf, stdin) != NULL) {

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strncmp(keyword, "[mod", 4)) {
			l = atoi(value);
			if (l == 0) {
				fprintf(stderr, "Error reading modulus: %s\n",
					buf);
				exit(1);
			}

			fputs(buf, stdout);
			fputs("\n", stdout);

			if (key != NULL)
				gnutls_privkey_deinit(key);

			ret = gnutls_privkey_init(&key);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret =
			    gnutls_privkey_generate(key, GNUTLS_PK_RSA,
						    l, 0);
			if (ret < 0) {
				fprintf(stderr, "error generating: %s\n", gnutls_strerror(ret));
				exit(1);
			}

			ret =
			    gnutls_privkey_export_rsa_raw(key, &n, &e, &d, NULL, NULL, NULL, NULL, NULL);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			do_bn_print_name(stdout, "n", &n);
			do_bn_print_name(stdout, "e", &e);
			do_bn_print_name(stdout, "d", &d);

			gnutls_free(n.data);
			gnutls_free(e.data);
			gnutls_free(d.data);

			continue;
		}

		if (!strcmp(keyword, "SHAAlg")) {
			if (strcmp(value, "SHA1") == 0) {
				hash = GNUTLS_DIG_SHA1;
			} else if (strcmp(value, "SHA256") == 0) {
				hash = GNUTLS_DIG_SHA256;
			} else if (strcmp(value, "SHA224") == 0) {
				hash = GNUTLS_DIG_SHA224;
			} else if (strcmp(value, "SHA384") == 0) {
				hash = GNUTLS_DIG_SHA384;
			} else if (strcmp(value, "SHA512") == 0) {
				hash = GNUTLS_DIG_SHA512;
			} else {
				fprintf(stderr, "unknown hash: %s\n", value);
				exit(1);
			}

			fputs(buf, stdout);
		} else if (!strcmp(keyword, "Msg")) {
			msg = hex2raw(value);

			putc('\n', stdout);
			fputs(buf, stdout);

			ret =
			    gnutls_privkey_sign_data(key, hash, 0, &msg, &sig);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			do_bn_print_name(stdout, "S", &sig);

			putc('\n', stdout);


		}
	}
}


int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "%s [keygen|keygen-seed|keyver|siggen|sigver]\n", argv[0]);
		exit(1);
	}
#ifdef REQUIRE_FIPS
	if (!gnutls_fips140_mode_enabled()) {
		do_print_errors();
		EXIT(1);
	}
#endif

	if (!strcmp(argv[1], "keygen"))
		keygen();
	else if (!strcmp(argv[1], "keygen-seed")) /* seed is given */
		keygen_seed();
	else if (!strcmp(argv[1], "keyver"))
		keyver();
	else if (!strcmp(argv[1], "sigver"))
		sigver();
	else if (!strcmp(argv[1], "siggen"))
		siggen();
	else {
		fprintf(stderr, "Don't know how to %s.\n", argv[1]);
		exit(1);
	}

	return 0;
}
