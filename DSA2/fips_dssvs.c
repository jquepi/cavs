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
#include "dsa-fips.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define USE_GMP
#include "fips_utl.h"

int _gnutls_dh_generate_key(gnutls_dh_params_t dh_params,
                            gnutls_datum_t *priv_key, gnutls_datum_t *pub_key);

int
_gnutls_encode_ber_rs_raw(gnutls_datum_t * sig_value,
                          const gnutls_datum_t * r, const gnutls_datum_t * s);

void pq(int *num, int l, int n)
{
int ret;
struct dsa_public_key pub;
struct dss_params_validation_seeds seeds;
int seed_len = (7 + n)/8;
uint8_t seed[MAX_PVP_SEED_SIZE];
mpz_t s, r;

	mpz_init(r);
	mpz_init(s);

	/* r = 2^(N-1) */
	mpz_set_ui(r, 1);
	mpz_mul_2exp (r, r, n - 1);

	while (*num) {
		--(*num);
		dsa_public_key_init(&pub);
		memset(&seeds, 0, sizeof(seeds));

		if (seed_len > MAX_PVP_SEED_SIZE) {
			do_print_errors();
			exit(1);
		}
		
		do {
			ret = gnutls_rnd(GNUTLS_RND_NONCE, seed, seed_len);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}
			nettle_mpz_set_str_256_u(s, seed_len, seed); 
		} while(mpz_cmp(s, r) < 0);

		ret = _dsa_generate_dss_pq(&pub, &seeds, seed_len, seed,
			NULL, NULL,
			l, n);
		if (ret == 0) {
			fprintf(stderr, "p_bits = %d, q_bits = %d, seed_length = %d\n", l, n, seed_len*8);
			do_print_errors();
			exit(1);
		}
		pbn("P", pub.p);
		pbn("Q", pub.q);
		pv("firstseed", seed, seed_len);
		pv("pseed", seeds.pseed, seeds.pseed_length);
		pv("qseed", seeds.qseed, seeds.qseed_length);
		printf("pgen_counter = %d\n", seeds.pgen_counter);
		printf("qgen_counter = %d\n", seeds.qgen_counter);
		//printf("Index = %d\n", (seeds.qgen_counter&1)+1);
		putc('\n', stdout);
		dsa_public_key_clear(&pub);
	}
	
	mpz_clear(r);
	mpz_clear(s);
}

enum {
	TEST_VALIDATE_G = 1,
	TEST_VALIDATE_PQ,
	TEST_GEN_PQ,
	TEST_GEN_G,
};

void merge_domain_seed(gnutls_datum_t *domain_seed, gnutls_datum_t *first_seed, gnutls_datum_t *p_seed, gnutls_datum_t *q_seed)
{
unsigned pos;

	domain_seed->size = first_seed->size + p_seed->size + q_seed->size;
	
	domain_seed->data = malloc(domain_seed->size);
	if (domain_seed->data == NULL) {
		do_print_errors();
		exit(1);
	}
	
	pos = 0;
	memcpy(&domain_seed->data[pos], first_seed->data, first_seed->size);
	pos += first_seed->size;
	memcpy(&domain_seed->data[pos], p_seed->data, p_seed->size);
	pos += p_seed->size;
	memcpy(&domain_seed->data[pos], q_seed->data, q_seed->size);
	pos += q_seed->size;
}

void pqg()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, ret;
	int n = 0;
	int num = 0, idx = 0;
	gnutls_datum_t q = {NULL, 0}, p = {NULL, 0};
	gnutls_datum_t domain_seed = {NULL, 0};
	gnutls_datum_t q_seed = {NULL, 0}, p_seed = {NULL, 0}, first_seed = {NULL, 0};
	unsigned make_g = 0;
	unsigned test = 0;
	int line = 0;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		line++;
		if (!strncmp(buf, "[A.1.2.1 ", 9)) {
			test = TEST_GEN_PQ;
		} else if (!strncmp(buf, "[A.2.3 ", 7)) {
			test = TEST_GEN_G;
		} else if (!strncmp(buf, "[A.2.", 5)) {
			fprintf(stderr, "unsupported mode: %s\n", buf);
			exit(1);
		}

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			printf("%s", buf);
			continue;
		}
		if (!strcmp(keyword, "[mod")) {
			if (sscanf(value, "L=%d, N=%d,", &l, &n) != 2) {
				fprintf(stderr, "Bad mod line\n");
				exit(1);
			}
			if (strstr(value, "SHA-384") == NULL) {
				fprintf(stderr, "Only SHA-384 is supported: %s\n", value);
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcmp(keyword, "Num")) {
			num = atoi(value);
			if (num == 0) {
				fprintf(stderr, "%d: Unacceptable num: %d\n", line, num);
				exit(1);
			}
			if (test != TEST_GEN_PQ) {
				fprintf(stderr, "%d: Num encountered at unknown state (skipping)!\n", line);
				continue;
			}
			pq(&num, l, n);	/* does its work only if num > 0 */
		} else if (!strcasecmp(keyword, "Index")) {
			idx = strtol(value, NULL, 16);
			printf("%s", buf);
			make_g = 1;
		} else if (!strcmp(keyword, "firstseed")) {
			first_seed = hex2raw(value);

			domain_seed.data = NULL;
			domain_seed.size = 0;

			if (first_seed.size > MAX_PVP_SEED_SIZE) {
				do_print_errors();
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcmp(keyword, "domain_parameter_seed")) {
			domain_seed = hex2raw(value);
			
			p_seed.data = q_seed.data = NULL;
			p_seed.size = q_seed.size = 0;
			
			printf("%s", buf);
		} else if (!strcmp(keyword, "pseed")) {
			p_seed = hex2raw(value);

			if (p_seed.size > MAX_PVP_SEED_SIZE) {
				do_print_errors();
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcmp(keyword, "qseed")) {
			q_seed = hex2raw(value);

			if (q_seed.size > MAX_PVP_SEED_SIZE) {
				do_print_errors();
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcmp(keyword, "P")) {
			p = hex2raw(value);
			printf("%s", buf);
		} else if (!strcmp(keyword, "Q")) {
			/* if Q exists we are asked to generate G */
			q = hex2raw(value);
			printf("%s", buf);
		} else
			printf("%s", buf);
		
		if (test == TEST_GEN_G && make_g != 0 && p.size > 0 && q.size > 0) {
			struct dsa_public_key pub;
			make_g = 0;

			dsa_public_key_init(&pub);
			nettle_mpz_set_str_256_u(pub.p, p.size, p.data); 
			nettle_mpz_set_str_256_u(pub.q, q.size, q.data); 

			if (domain_seed.size == 0) {
				merge_domain_seed(&domain_seed, &first_seed, &p_seed, &q_seed);
			}

			ret = _dsa_generate_dss_g(&pub,
				domain_seed.size, domain_seed.data, NULL, NULL, idx);
			if (ret == 0) {
				do_print_errors();
				exit(1);
			}

			pbn("G", pub.g);
			putc('\n', stdout);
			dsa_public_key_clear(&pub);
		}
	}
}


void pqgver()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, ret;
	int n = 0;
	int idx = 0;
	gnutls_datum_t q = {NULL, 0}, p = {NULL, 0};
	gnutls_datum_t g = {NULL, 0};
	gnutls_datum_t domain_seed = {NULL, 0};
	gnutls_datum_t q_seed = {NULL, 0}, p_seed = {NULL, 0}, first_seed = {NULL, 0};
	unsigned validate_g = 0, validate_pq = 0;
	unsigned test = 0;
	int qgen_counter = 0, pgen_counter = 0;
	struct dss_params_validation_seeds seeds;
	struct dsa_public_key pub;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!strncmp(buf, "[A.1.2.2 ", 9)) {
			test = TEST_VALIDATE_PQ;
		} else if (!strncmp(buf, "[A.2.4 ", 7)) {
			test = TEST_VALIDATE_G;
		}

		if (!parse_line(&keyword, &value, lbuf, buf)) {
			printf("%s", buf);
			continue;
		}
		if (!strcmp(keyword, "[mod")) {
			if (sscanf(value, "L=%d, N=%d,", &l, &n) != 2) {
				fprintf(stderr, "Bad mod line\n");
				exit(1);
			}
			if (strstr(value, "SHA-384") == NULL) {
				fprintf(stderr, "Only SHA-384 is supported: %s\n", value);
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcasecmp(keyword, "Index")) {
			idx = strtol(value, NULL, 16);
			printf("%s", buf);
		} else if (!strcmp(keyword, "pgen_counter")) {
			pgen_counter = atoi(value);
			printf("%s", buf);
		} else if (!strcmp(keyword, "qgen_counter")) {
			qgen_counter = atoi(value);
			printf("%s", buf);
			validate_pq = 1;
		} else if (!strcmp(keyword, "firstseed")) {
			first_seed = hex2raw(value);

			domain_seed.data = NULL;
			domain_seed.size = 0;

			if (first_seed.size > MAX_PVP_SEED_SIZE) {
				do_print_errors();
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcmp(keyword, "domain_parameter_seed")) {
			domain_seed = hex2raw(value);

			p_seed.data = q_seed.data = NULL;
			p_seed.size = q_seed.size = 0;
			
			printf("%s", buf);
			validate_g = 1;
		} else if (!strcmp(keyword, "pseed")) {
			p_seed = hex2raw(value);

			if (p_seed.size > MAX_PVP_SEED_SIZE) {
				do_print_errors();
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcmp(keyword, "qseed")) {
			q_seed = hex2raw(value);

			if (q_seed.size > MAX_PVP_SEED_SIZE) {
				do_print_errors();
				exit(1);
			}
			printf("%s", buf);
		} else if (!strcmp(keyword, "P")) {
			p = hex2raw(value);
			printf("%s", buf);
			
			if (p.size != l/8) {
				fprintf(stderr, "Invalid bit size of p (%d)\n", p.size*8);
				exit(1);
			}
		} else if (!strcmp(keyword, "G")) {
			g = hex2raw(value);
			printf("%s", buf);
		} else if (!strcmp(keyword, "Q")) {
			/* if Q exists we are asked to generate G */
			q = hex2raw(value);
			printf("%s", buf);

			if (q.size != n/8) {
				fprintf(stderr, "Invalid bit size of q (%d)\n", q.size*8);
				exit(1);
			}
		} else 
			printf("%s", buf);
		
		if (test == TEST_VALIDATE_PQ && validate_pq != 0 && p.size > 0 && q.size > 0) {
			validate_pq = 0;

			memset(&seeds, 0, sizeof(seeds));
			if (first_seed.size > 0)
				memcpy(seeds.seed, first_seed.data, first_seed.size);
			seeds.seed_length = first_seed.size;

			if (p_seed.size > 0)
				memcpy(seeds.pseed, p_seed.data, p_seed.size);
			seeds.pseed_length = p_seed.size;

			if (q_seed.size > 0)
				memcpy(seeds.qseed, q_seed.data, q_seed.size);
			seeds.qseed_length = q_seed.size;
			
			seeds.pgen_counter = pgen_counter;
			seeds.qgen_counter = qgen_counter;
			
			dsa_public_key_init(&pub);
			nettle_mpz_set_str_256_u(pub.p, p.size, p.data); 
			nettle_mpz_set_str_256_u(pub.q, q.size, q.data); 

			ret = _dsa_validate_dss_pq(&pub, &seeds);
			if (ret == 0) {
				printf("Result = F\n");
			} else {
				printf("Result = P\n");
			}
			putc('\n', stdout);
			dsa_public_key_clear(&pub);
		}
		
		if (test == TEST_VALIDATE_G && validate_g != 0 && p.size > 0 && q.size > 0) {
			validate_g = 0;
			
			dsa_public_key_init(&pub);
			nettle_mpz_set_str_256_u(pub.p, p.size, p.data); 
			nettle_mpz_set_str_256_u(pub.q, q.size, q.data); 
			nettle_mpz_set_str_256_u(pub.g, g.size, g.data);
			
			if (domain_seed.size == 0) {
				merge_domain_seed(&domain_seed, &first_seed, &p_seed, &q_seed);
			}

			ret = _dsa_validate_dss_g(&pub, domain_seed.size, domain_seed.data, idx);
			if (ret == 0) {
				printf("Result = F\n");
			} else {
				printf("Result = P\n");
			}
			putc('\n', stdout);
			dsa_public_key_clear(&pub);
		}
	}
}

static void random_func(void *ctx, unsigned length, uint8_t *dst)
{
	if (gnutls_rnd(GNUTLS_RND_NONCE, dst, length) < 0) {
		do_print_errors();
		exit(1);
	}
}

void keypair()
{
	char buf[1024];
	char lbuf[1024];
	char *keyword, *value;
	int l = 0, n = 0, ret;
	gnutls_datum_t p = {NULL,0}, q = {NULL,0}, g = {NULL,0};

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}
		if (!strcmp(keyword, "[mod")) {
			if (sscanf(value, "L=%d, N=%d", &l, &n) != 2) {
				fprintf(stderr, "Bad mod line\n");
				exit(1);
			}
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "N")) {
			gnutls_privkey_t key;
			struct dsa_private_key pkey;
			struct dsa_public_key pub;
			int num = atoi(value);

			ret = gnutls_privkey_init(&key);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_privkey_generate(key, GNUTLS_PK_DSA, GNUTLS_SUBGROUP_TO_BITS(l,n), 0);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			ret = gnutls_privkey_export_dsa_raw(key, &p, &q, &g, NULL, NULL); 
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}

			do_bn_print_name(stdout, "P", &p);
			do_bn_print_name(stdout, "Q", &q);
			do_bn_print_name(stdout, "G", &g);
			putc('\n', stdout);


			while (num--) {
				dsa_public_key_init(&pub);
				dsa_private_key_init(&pkey);

				nettle_mpz_set_str_256_u(pub.p, p.size, p.data); 
				nettle_mpz_set_str_256_u(pub.q, q.size, q.data); 
				nettle_mpz_set_str_256_u(pub.g, g.size, g.data); 

				if (dsa_generate_dss_keypair(&pub, &pkey, NULL, random_func, NULL, NULL) != 1) {
					fprintf(stderr, "error in %s:%d\n", __func__, __LINE__);
					exit(1);
				}

				pbn("X", pkey.x);
				pbn("Y", pub.y);
				putc('\n', stdout);

				dsa_private_key_clear(&pkey);
				dsa_public_key_clear(&pub);
			}

			gnutls_free(p.data);
			gnutls_free(g.data);
			gnutls_free(q.data);
			gnutls_privkey_deinit(key);
		}
	}
}

void siggen()
{
	gnutls_privkey_t key = NULL;
	char buf[1024];
	char lbuf[1024];
	int l = 0, n = 0;
	char *keyword, *value;
	int ret;
	unsigned hash = 0;
	unsigned lineno = 0;
	gnutls_datum_t p = {NULL,0}, q = {NULL,0}, g = {NULL,0};
	gnutls_datum_t y = {NULL,0}, x = {NULL,0};
	gnutls_datum_t r = {NULL,0}, s = {NULL,0};
	gnutls_datum_t msg = {NULL,0};
	gnutls_datum_t sig;
	struct asn1_der_iterator ider;
	unsigned generate_new_key = 0;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		lineno++;
		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}
		if (!strcmp(keyword, "[mod")) {
			if (sscanf(value, "L=%d, N=%d", &l, &n) != 2) {
				fprintf(stderr, "Bad mod line: %d\n", lineno);
				exit(1);
			}

			if (strstr(value, "SHA-1") != NULL) {
				hash = GNUTLS_DIG_SHA1;
			} else if (strstr(value, "SHA-224") != NULL) {
				hash = GNUTLS_DIG_SHA224;
			} else if (strstr(value, "SHA-256") != NULL) {
				hash = GNUTLS_DIG_SHA256;
			} else if (strstr(value, "SHA-384") != NULL) {
				hash = GNUTLS_DIG_SHA384;
			} else if (strstr(value, "SHA-512") != NULL) {
				hash = GNUTLS_DIG_SHA512;
			} else {
				fprintf(stderr, "Unsupported hash: %s\n", value);
				exit(1);
			}

			if (key != NULL) {
				gnutls_free(y.data);
				y.data = NULL;
				gnutls_privkey_deinit(key);
			}
			generate_new_key = 1;

			fputs(buf, stdout);
		} else if (!strcmp(keyword, "Msg")) {
			msg = hex2raw(value);
	
			if (generate_new_key != 0) {
				generate_new_key = 0;
				ret = gnutls_privkey_init(&key);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}

				ret = gnutls_privkey_generate(key, GNUTLS_PK_DSA, GNUTLS_SUBGROUP_TO_BITS(l,n), 0);
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}


				ret = gnutls_privkey_export_dsa_raw(key, &p, &q, &g, &y, &x); 
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}
				do_bn_print_name(stdout, "P", &p);
				do_bn_print_name(stdout, "Q", &q);
				do_bn_print_name(stdout, "G", &g);
				putc('\n', stdout);

				//do_bn_print_name(stdout, "X", &x);
			}

			ret = gnutls_privkey_sign_data(key, hash, 0, &msg, &sig);
			if (ret < 0) {
				fprintf(stderr, "error in line %d\n", lineno);
				do_print_errors();
				exit(1);
			}

			fputs(buf, stdout);
#if 0
			do_bn_print_name(stdout, "SIG", &sig);
#endif
			do_bn_print_name(stdout, "Y", &y);
			
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

			gnutls_free(p.data);
			p.data = NULL;
			gnutls_free(q.data);
			q.data = NULL;
			gnutls_free(g.data);
			g.data = NULL;
			gnutls_free(x.data);
			x.data = NULL;
			gnutls_free(sig.data);
			sig.data = NULL;
	
		}
	}
}

void sigver()
{
	gnutls_pubkey_t key;
	char buf[1024];
	char lbuf[1024];
	int l = 0, n = 0;
	char *keyword, *value;
	int ret;
	unsigned sig_algo = 0;
	gnutls_datum_t p = {NULL,0}, q = {NULL,0}, g = {NULL,0};
	gnutls_datum_t y = {NULL,0};
	gnutls_datum_t r = {NULL,0}, s = {NULL,0};
	gnutls_datum_t msg = {NULL,0};
	gnutls_datum_t sig;

	while (fgets(buf, sizeof buf, stdin) != NULL) {
		if (!parse_line(&keyword, &value, lbuf, buf)) {
			fputs(buf, stdout);
			continue;
		}
		if (!strcmp(keyword, "[mod")) {
			if (sscanf(value, "L=%d, N=%d", &l, &n) != 2) {
				fprintf(stderr, "Bad mod line\n");
				exit(1);
			}

			if (strstr(value, "SHA-1") != NULL) {
				sig_algo = GNUTLS_SIGN_DSA_SHA;
			} else if (strstr(value, "SHA-224") != NULL) {
				sig_algo = GNUTLS_SIGN_DSA_SHA224;
			} else if (strstr(value, "SHA-256") != NULL) {
				sig_algo = GNUTLS_SIGN_DSA_SHA256;
			} else if (strstr(value, "SHA-384") != NULL) {
				sig_algo = GNUTLS_SIGN_DSA_SHA384;
			} else if (strstr(value, "SHA-512") != NULL) {
				sig_algo = GNUTLS_SIGN_DSA_SHA512;
			} else {
				fprintf(stderr, "Unsupported hash: %s\n", value);
				exit(1);
			}

			fputs(buf, stdout);
		} else if (!strcmp(keyword, "P")) {
			p = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "Q")) {
			q = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "G")) {
			g = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "Msg")) {
			msg = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "Y")) {
			y = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "R")) {
			r = hex2raw(value);
			fputs(buf, stdout);
		} else if (!strcmp(keyword, "S")) {
			s = hex2raw(value);
			fputs(buf, stdout);

			ret = gnutls_pubkey_init(&key);
			if (ret < 0) {
				do_print_errors();
				exit(1);
			}
			
			ret = gnutls_pubkey_import_dsa_raw(key, &p, &q, &g, &y);
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
			} else {
				printf("Result = P\n");
			}
			putc('\n', stdout);
			
			gnutls_free(sig.data);
			gnutls_free(s.data);
			gnutls_free(r.data);
			
			gnutls_pubkey_deinit(key);
		}
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "%s [pqg|pqgver|keypair|siggen|sigver]\n", argv[0]);
		exit(1);
	}

#ifdef REQUIRE_FIPS
	if (!gnutls_fips140_mode_enabled()) {
		do_print_errors();
		EXIT(1);
	}
#endif

	if (!strcmp(argv[1], "pqg"))
		pqg();
	else if (!strcmp(argv[1], "pqgver"))
		pqgver();
	else if (!strcmp(argv[1], "keypair"))
		keypair();
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
