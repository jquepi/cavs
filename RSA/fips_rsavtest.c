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

static void pbn(const char *name, mpz_t n)
{
	if ((mpz_sizeinbase(n, 16) % 2) == 0)
		gmp_printf("%s = %Zx\n", name, n);
	else
		gmp_printf("%s = 0%Zx\n", name, n);
	return;
}

#define METHOD "[PrimeMethod"

void keygen()
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
	struct rsa_public_key pub;
	struct rsa_private_key priv;

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

		if (!strcmp(keyword, "e")) {
			e = hex2raw(value);
			printf("%s", buf);
		} else if (!strcmp(keyword, "seed")) {
			seed = hex2raw(value);
			printf("%s", buf);

			rsa_public_key_init(&pub);
			rsa_private_key_init(&priv);

			/* set e */
			nettle_mpz_set_str_256_u(pub.e, e.size, e.data);

			ret = _rsa_generate_fips186_4_keypair(&pub, &priv,
							      seed.size,
							      seed.data, NULL,
							      NULL, l);
			if (ret == 0) {
				do_print_errors();
				exit(1);
			}

			pbn("p", priv.p);
			pbn("q", priv.q);
			pbn("n", pub.n);
			pbn("d", priv.d);
			putc('\n', stdout);
			fflush(stdout);
			rsa_private_key_clear(&priv);
			rsa_public_key_clear(&pub);
		}
	}
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
	gnutls_datum_t s = { NULL, 0 };
	gnutls_datum_t msg = { NULL, 0 };
	gnutls_datum_t sig;
	unsigned hash = 0;
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
				hash = GNUTLS_DIG_SHA1;
				sig_algo = GNUTLS_SIGN_RSA_SHA1;
			} else if (strcmp(value, "SHA256") == 0) {
				hash = GNUTLS_DIG_SHA256;
				sig_algo = GNUTLS_SIGN_RSA_SHA256;
			} else if (strcmp(value, "SHA224") == 0) {
				hash = GNUTLS_DIG_SHA224;
				sig_algo = GNUTLS_SIGN_RSA_SHA224;
			} else if (strcmp(value, "SHA384") == 0) {
				hash = GNUTLS_DIG_SHA384;
				sig_algo = GNUTLS_SIGN_RSA_SHA384;
			} else if (strcmp(value, "SHA512") == 0) {
				hash = GNUTLS_DIG_SHA512;
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
			hash = 0;
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
		fprintf(stderr, "%s [keypair|siggen|sigver|pkv]\n", argv[0]);
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
