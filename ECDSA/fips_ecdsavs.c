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
#include <nettle/dsa.h>
#include <nettle/asn1.h>
#include <nettle/bignum.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

int
_gnutls_encode_ber_rs_raw(gnutls_datum_t * sig_value,
                          const gnutls_datum_t * r, const gnutls_datum_t * s);

void keypair()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, ret;
	gnutls_datum_t k = {NULL,0};
	gnutls_datum_t y = {NULL,0}, x = {NULL,0};
	unsigned curve = 0;
	gnutls_ecc_curve_t tc;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!strncmp(buf, "[P-", 3)) {
			l = atoi(buf+3);
			if (l == 256) {
				curve = GNUTLS_ECC_CURVE_SECP256R1;
			} else if (l == 384) {
				curve = GNUTLS_ECC_CURVE_SECP384R1;
			} else if (l == 521) {
				curve = GNUTLS_ECC_CURVE_SECP521R1;
			} else {
				fprintf(stderr, "Unsupported curve: %s\n", buf);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		} else if (buf[0] == '[' && buf[1] != 'B') {
			fprintf(stderr, "Unexpected line: %s\n", buf);
		}

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strcmp(keyword, "N")) {
			gnutls_privkey_t key;
			int num = atoi(value);

			while (num--) {
				ret = gnutls_privkey_init(&key);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}

				ret = gnutls_privkey_generate(key, GNUTLS_PK_EC, GNUTLS_CURVE_TO_BITS(curve), 0);
				if (ret < 0) {
					fprintf(stderr, "error generating key: %s\n", gnutls_strerror(ret));
					do_print_errors();
					exit(1);
				}

				ret = gnutls_privkey_export_ecc_raw(key, &tc, &x, &y, &k);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}

				do_bn_print_name(stdout, "d", &k);
				do_bn_print_name(stdout, "Qx", &x);
				do_bn_print_name(stdout, "Qy", &y);
				putc('\n', stdout);
			
				gnutls_privkey_deinit(key);
				gnutls_free(x.data);
				gnutls_free(y.data);
				gnutls_free(k.data);
			}
		}
	}
}

void pkver()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, ret;
	gnutls_datum_t k = {NULL,0};
	gnutls_datum_t y = {NULL,0}, x = {NULL,0};
	unsigned curve = 0;
	gnutls_pubkey_t key;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!strncmp(buf, "[P-", 3)) {
			l = atoi(buf+3);
			if (l == 256) {
				curve = GNUTLS_ECC_CURVE_SECP256R1;
			} else if (l == 384) {
				curve = GNUTLS_ECC_CURVE_SECP384R1;
			} else if (l == 521) {
				curve = GNUTLS_ECC_CURVE_SECP521R1;
			} else {
				fprintf(stderr, "Unsupported curve: %s\n", buf);
				exit(1);
			}
			fputs(buf, stdout);
			continue;
		} else if (buf[0] == '[') {
			fprintf(stderr, "Unsupported curve: %s\n", buf);
			exit(1);
		}

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strcmp(keyword, "Qx")) {
			x = hex2raw(value);

			printf("%s", buf);
		} else if (!strcmp(keyword, "Qy")) {
			y = hex2raw(value);

			printf("%s", buf);

			ret = gnutls_pubkey_init(&key);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_pubkey_import_ecc_raw(key, curve, &x, &y);
			if (ret < 0) {
				fprintf(stderr, "error importing key: %s\n", gnutls_strerror(ret));
				do_print_errors();
				exit(1);
			}

			do_bn_print_name(stdout, "Qx", &x);
			do_bn_print_name(stdout, "Qy", &y);
			
			ret = gnutls_pubkey_verify_params(key);
			if (ret < 0) {
				printf("Result = F\n");
			} else
				printf("Result = P\n");

			gnutls_pubkey_deinit(key);
			gnutls_free(x.data);
			gnutls_free(y.data);
			gnutls_free(k.data);
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
	gnutls_datum_t k = {NULL,0};
	gnutls_datum_t y = {NULL,0}, x = {NULL,0};
	gnutls_datum_t r = {NULL,0}, s = {NULL,0};
	gnutls_datum_t msg = {NULL,0};
	gnutls_datum_t sig;
	unsigned curve = 0, hash = 0;
	gnutls_ecc_curve_t tc;
	struct asn1_der_iterator ider;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!strncmp(buf, "[P-", 3)) {
			l = atoi(buf+3);
			if (l == 256) {
				curve = GNUTLS_ECC_CURVE_SECP256R1;
			} else if (l == 384) {
				curve = GNUTLS_ECC_CURVE_SECP384R1;
			} else if (l == 521) {
				curve = GNUTLS_ECC_CURVE_SECP521R1;
			} else {
				fprintf(stderr, "Unsupported curve: %s\n", buf);
				exit(1);
			}

			if (strstr(buf, "SHA-1") != 0) {
				hash = GNUTLS_DIG_SHA1;
			} else if (strstr(buf, "SHA-224") != 0) {
				hash = GNUTLS_DIG_SHA224;
			} else if (strstr(buf, "SHA-256") != 0) {
				hash = GNUTLS_DIG_SHA256;
			} else if (strstr(buf, "SHA-384") != 0) {
				hash = GNUTLS_DIG_SHA384;
			} else if (strstr(buf, "SHA-512") != 0) {
				hash = GNUTLS_DIG_SHA512;
			} else {
				fprintf(stderr, "unknown hash algo: %s\n", buf);
				exit(1);
			}

			fputs(buf, stdout);
			fputs("\n", stdout);

			continue;
		} else if (buf[0] == '[') {
			fprintf(stderr, "Unsupported curve: %s\n", buf);
			exit(1);
		}

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}

		if (!strcmp(keyword, "Msg")) {
			msg = hex2raw(value);

			ret = gnutls_privkey_init(&key);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_privkey_generate(key, GNUTLS_PK_EC, GNUTLS_CURVE_TO_BITS(curve), 0);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_privkey_export_ecc_raw(key, &tc, &x, &y, &k); 
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}


			ret = gnutls_privkey_sign_data(key, hash, 0, &msg, &sig);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			fputs(buf, stdout);
			do_bn_print_name(stdout, "Qx", &x);
			do_bn_print_name(stdout, "Qy", &y);
#if 0
			do_bn_print_name(stdout, "SIG", &sig);
#endif
			
			/* break sig into r, s */
			ret = asn1_der_iterator_first(&ider, sig.size, sig.data);
			if (ret != ASN1_ITERATOR_CONSTRUCTED || ider.type != ASN1_SEQUENCE) {
				do_print_errors();
				exit(1);
			}

			ret = asn1_der_decode_constructed_last(&ider);
			if (ret != ASN1_ITERATOR_PRIMITIVE || ider.type != ASN1_INTEGER) {
				do_print_errors();
				exit(1);
			}
			r.data = (void*)ider.data;
			r.size = ider.length;

			do_bn_print_name(stdout, "R", &r);

			ret = asn1_der_iterator_next(&ider);
			if (ret != ASN1_ITERATOR_PRIMITIVE || ider.type != ASN1_INTEGER) {
				do_print_errors();
				exit(1);
			}

			s.data = (void*)ider.data;
			s.size = ider.length;

			do_bn_print_name(stdout, "S", &s);

			ret = asn1_der_iterator_next(&ider);
			if (ret != ASN1_ITERATOR_END) {
				do_print_errors();
				exit(1);
			}

			putc('\n', stdout);

			gnutls_free(x.data);
			gnutls_free(y.data);
			gnutls_free(sig.data);
			
			gnutls_privkey_deinit(key);
			key = NULL;
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
	unsigned sig_algo = 0;
	gnutls_datum_t x = {NULL,0}, y = {NULL,0};
	gnutls_datum_t r = {NULL,0}, s = {NULL,0};
	gnutls_datum_t msg = {NULL,0};
	gnutls_datum_t sig;
	unsigned curve = 0;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!strncmp(buf, "[P-", 3)) {
			l = atoi(buf+3);
			if (l == 256) {
				curve = GNUTLS_ECC_CURVE_SECP256R1;
			} else if (l == 384) {
				curve = GNUTLS_ECC_CURVE_SECP384R1;
			} else if (l == 521) {
				curve = GNUTLS_ECC_CURVE_SECP521R1;
			} else {
				fprintf(stderr, "Unsupported curve: %s\n", buf);
				exit(1);
			}
			if (strstr(buf, "SHA-1") != 0) {
				sig_algo = GNUTLS_SIGN_ECDSA_SHA1;
			} else if (strstr(buf, "SHA-224") != 0) {
				sig_algo = GNUTLS_SIGN_ECDSA_SHA224;
			} else if (strstr(buf, "SHA-256") != 0) {
				sig_algo = GNUTLS_SIGN_ECDSA_SHA256;
			} else if (strstr(buf, "SHA-384") != 0) {
				sig_algo = GNUTLS_SIGN_ECDSA_SHA384;
			} else if (strstr(buf, "SHA-512") != 0) {
				sig_algo = GNUTLS_SIGN_ECDSA_SHA512;
			} else {
				fprintf(stderr, "unknown signature algo: %s\n", buf);
				exit(1);
			}

			fputs(buf, stdout);
			fputs("\n", stdout);

			continue;
		} else if (buf[0] == '[') {
			fprintf(stderr, "Unsupported curve: %s\n", buf);
			exit(1);
		}

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}
		if (!strcmp(keyword, "Msg")) {
			msg = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "Qx")) {
			x = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "Qy")) {
			y = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "R")) {
			r = hex2raw_u(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "S")) {
			s = hex2raw_u(value);
			fputs(buf, stdout);

			ret = gnutls_pubkey_init(&key);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}
			
			ret = gnutls_pubkey_import_ecc_raw(key, curve, &x, &y);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}
			
			ret = _gnutls_encode_ber_rs_raw(&sig, &r, &s);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_pubkey_verify_data2(key, sig_algo, 0, &msg, &sig);
			if (ret < 0) {
				printf("Result = F\n");
				//printf("Result = F (curve: %s)\n", gnutls_ecc_curve_get_name(curve));
			} else {
				printf("Result = P\n");
			}
			putc('\n', stdout);
			
			gnutls_free(sig.data);
			gnutls_free(s.data);
			gnutls_free(r.data);
			
			gnutls_pubkey_deinit(key);
			fflush(stderr);
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

	if (!strcmp(argv[1], "keypair"))
		keypair();
	else if (!strcmp(argv[1], "pkv"))
		pkver();
	else if (!strcmp(argv[1], "siggen"))
		siggen();
	else if (!strcmp(argv[1], "sigver"))
		sigver();
	else {
		fprintf(stderr, "Don't know how to %s.\n", argv[1]);
		exit(1);
	}

	return 0;
}
