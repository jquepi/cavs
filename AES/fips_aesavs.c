/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 */
/*---------------------------------------------
  NIST AES Algorithm Validation Suite
  Test Program

  Donated to OpenSSL by:
  V-ONE Corporation
  20250 Century Blvd, Suite 300
  Germantown, MD 20874
  U.S.A.
  ----------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "fips_utl.h"

#define AES_BLOCK_SIZE 16

#define VERBOSE 0

/*-----------------------------------------------*/

int AESTest(gnutls_cipher_hd_t * ctx, char *amode, int akeysz, unsigned char *aKey, unsigned char *iVec, int dir,	/* 0 = decrypt, 1 = encrypt */
	    unsigned char *plaintext, unsigned char *ciphertext, int len)
{
	int ret;
	gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_UNKNOWN;
	gnutls_datum_t key, iv;

	if (strcasecmp(amode, "CBC") == 0) {
		switch (akeysz) {
		case 128:
			cipher = GNUTLS_CIPHER_AES_128_CBC;
			break;

		case 192:
			cipher = GNUTLS_CIPHER_AES_192_CBC;
			break;

		case 256:
			cipher = GNUTLS_CIPHER_AES_256_CBC;
			break;
		}
	} else {
		printf("Unknown mode: %s\n", amode);
		return 0;
	}
	if (cipher == GNUTLS_CIPHER_UNKNOWN) {
		printf("Invalid key size: %d\n", akeysz);
		return 0;
	}

	key.data = aKey;
	key.size = akeysz / 8;

	iv.data = iVec;
	iv.size = 16;
	ret = gnutls_cipher_init(ctx, cipher, &key, &iv);
	if (ret < 0) {
		do_print_errors();
		return 0;
	}
	if (dir)
		ret =
		    gnutls_cipher_encrypt2(*ctx, plaintext, len, ciphertext,
					   len);
	else
		ret =
		    gnutls_cipher_decrypt2(*ctx, ciphertext, len, plaintext,
					   len);

	if (ret < 0) {
		do_print_errors();
		return 0;
	}
	return 1;
}

/*-----------------------------------------------*/
#define T_MODES 1
char *t_tag[2] = { "PLAINTEXT", "CIPHERTEXT" };
char *t_mode[T_MODES] = { "CBC" };
enum Mode { CBC };
enum XCrypt { XDECRYPT, XENCRYPT };

/*=============================*/
/*  Monte Carlo Tests          */
/*-----------------------------*/

/*#define gb(a,b) (((a)[(b)/8] >> ((b)%8))&1)*/
/*#define sb(a,b,v) ((a)[(b)/8]=((a)[(b)/8]&~(1 << ((b)%8)))|(!!(v) << ((b)%8)))*/

#define gb(a,b) (((a)[(b)/8] >> (7-(b)%8))&1)
#define sb(a,b,v) ((a)[(b)/8]=((a)[(b)/8]&~(1 << (7-(b)%8)))|(!!(v) << (7-(b)%8)))

int do_mct(char *amode,
	   int akeysz, unsigned char *aKey, unsigned char *iVec,
	   int dir, unsigned char *text, int len, FILE * rfp)
{
	int ret = 0;
	unsigned char key[101][32];
	unsigned char iv[101][AES_BLOCK_SIZE];
	unsigned char ptext[1001][32];
	unsigned char ctext[1001][32];
	unsigned char ciphertext[64 + 4];
	int i, j, n, n1, n2;
	int imode = 0, nkeysz = akeysz / 8;
	gnutls_cipher_hd_t ctx;

	if (len > 32) {
		printf("\n>>>> Length exceeds 32 for %s %d <<<<\n\n",
		       amode, akeysz);
		return -1;
	}
	for (imode = 0; imode < T_MODES; ++imode)
		if (strcmp(amode, t_mode[imode]) == 0)
			break;
	if (imode == T_MODES) {
		printf("Unrecognized mode: %s\n", amode);
		return -1;
	}

	memcpy(key[0], aKey, nkeysz);
	if (iVec)
		memcpy(iv[0], iVec, AES_BLOCK_SIZE);
	if (dir == XENCRYPT)
		memcpy(ptext[0], text, len);
	else
		memcpy(ctext[0], text, len);
	for (i = 0; i < 100; ++i) {
		/* printf("Iteration %d\n", i); */
		if (i > 0) {
			fprintf(rfp, "COUNT = %d\n", i);
			OutputValue("KEY", key[i], nkeysz, rfp, 0);
#if 0
			if (imode != ECB)	/* ECB */
#endif
				OutputValue("IV", iv[i], AES_BLOCK_SIZE, rfp,
					    0);
			/* Output Ciphertext | Plaintext */
			OutputValue(t_tag[dir ^ 1], dir ? ptext[0] : ctext[0],
				    len, rfp, 0);
		}
		for (j = 0; j < 1000; ++j) {
			switch (imode) {
			case CBC:
				if (j == 0) {
					ret = AESTest(&ctx, amode, akeysz, key[i], iv[i], dir,	/* 0 = decrypt, 1 = encrypt */
						      ptext[j], ctext[j], len);
					if (dir == XENCRYPT)
						memcpy(ptext[j + 1], iv[i],
						       len);
					else
						memcpy(ctext[j + 1], iv[i],
						       len);
				} else {
					if (dir == XENCRYPT) {
						ret =
						    gnutls_cipher_encrypt2(ctx,
									   ptext
									   [j],
									   len,
									   ctext
									   [j],
									   len);
						memcpy(ptext[j + 1],
						       ctext[j - 1], len);
					} else {
						ret =
						    gnutls_cipher_decrypt2(ctx,
									   ctext
									   [j],
									   len,
									   ptext
									   [j],
									   len);
						memcpy(ctext[j + 1],
						       ptext[j - 1], len);
					}
				}

				if (ret < 0) {
					do_print_errors();
					return 0;
				}
				break;
			}
		}
		--j;		/* reset to last of range */
		/* Output Ciphertext | Plaintext */
		OutputValue(t_tag[dir], dir ? ctext[j] : ptext[j], len, rfp, 0);
		fprintf(rfp, "\n");	/* add separator */

		/* Compute next KEY */
		if (dir == XENCRYPT) {
			switch (akeysz) {
			case 128:
				memcpy(ciphertext, ctext[j], 16);
				break;
			case 192:
				memcpy(ciphertext, ctext[j - 1] + 8, 8);
				memcpy(ciphertext + 8, ctext[j], 16);
				break;
			case 256:
				memcpy(ciphertext, ctext[j - 1], 16);
				memcpy(ciphertext + 16, ctext[j], 16);
				break;
			}
		} else {
			switch (akeysz) {
			case 128:
				memcpy(ciphertext, ptext[j], 16);
				break;
			case 192:
				memcpy(ciphertext, ptext[j - 1] + 8, 8);
				memcpy(ciphertext + 8, ptext[j], 16);
				break;
			case 256:
				memcpy(ciphertext, ptext[j - 1], 16);
				memcpy(ciphertext + 16, ptext[j], 16);
				break;
			}
		}
		/* Compute next key: Key[i+1] = Key[i] xor ct */
		for (n = 0; n < nkeysz; ++n)
			key[i + 1][n] = key[i][n] ^ ciphertext[n];

		/* Compute next IV and text */
		if (dir == XENCRYPT) {
			switch (imode) {
			case CBC:
				memcpy(iv[i + 1], ctext[j], AES_BLOCK_SIZE);
				memcpy(ptext[0], ctext[j - 1], AES_BLOCK_SIZE);
				break;
			}
		} else {
			switch (imode) {
			case CBC:
				memcpy(iv[i + 1], ptext[j], AES_BLOCK_SIZE);
				memcpy(ctext[0], ptext[j - 1], AES_BLOCK_SIZE);
				break;
			}
		}
	}

	gnutls_cipher_deinit(ctx);
	return ret;
}

/*================================================*/
/*----------------------------
  # Config info for v-one
  # AESVS MMT test data for ECB
  # State : Encrypt and Decrypt
  # Key Length : 256
  # Fri Aug 30 04:07:22 PM
  ----------------------------*/

int proc_file(char *rqfile, char *rspfile)
{
	char afn[256], rfn[256];
	FILE *afp = NULL, *rfp = NULL;
	char ibuf[2048];
	char tbuf[2048];
	int ilen, len, ret = 0;
	char algo[8] = "";
	char amode[8] = "";
	char atest[8] = "";
	int akeysz = 0;
	unsigned char iVec[20], aKey[40];
	int dir = -1, err = 0, step = 0;
	unsigned char plaintext[2048];
	unsigned char ciphertext[2048];
	char *rp;
	gnutls_cipher_hd_t ctx;

	if (!rqfile || !(*rqfile)) {
		printf("No req file\n");
		return -1;
	}
	strcpy(afn, rqfile);

	if ((afp = fopen(afn, "r")) == NULL) {
		printf("Cannot open file: %s, %s\n", afn, strerror(errno));
		return -1;
	}
	if (!rspfile) {
		strcpy(rfn, afn);
		rp = strstr(rfn, "req/");
#ifdef _WIN32
		if (!rp)
			rp = strstr(rfn, "req\\");
#endif
		if (!rp) {
			printf("No req in req file path\n");
			return -1;
		}
		memcpy(rp, "resp", 4);
		strcpy(rp + 4, afn + (rp - rfn) + 3);
		rp = strstr(rfn, ".req");
		memcpy(rp, ".rsp", 4);
		rspfile = rfn;
	}
	if ((rfp = fopen(rspfile, "w")) == NULL) {
		printf("Cannot open file: %s, %s\n", rfn, strerror(errno));
		fclose(afp);
		afp = NULL;
		return -1;
	}
	while (!err && (fgets(ibuf, sizeof(ibuf), afp)) != NULL) {
		tidy_line(tbuf, ibuf);
		ilen = strlen(ibuf);
		/*      printf("step=%d ibuf=%s",step,ibuf); */
		switch (step) {
		case 0:	/* read preamble */
			if (ibuf[0] == '\n' || ibuf[0] == '\r') {	/* end of preamble */
				if ((*algo == '\0') ||
				    (*amode == '\0') || (akeysz == 0)) {
					printf
					    ("Missing Algorithm, Mode or KeySize (%s/%s/%d)\n",
					     algo, amode, akeysz);
					err = 1;
				} else {
					fputs(ibuf, rfp);
					++step;
				}
			} else if (ibuf[0] != '#') {
				printf("Invalid preamble item: %s\n", ibuf);
				err = 1;
			} else {	/* process preamble */
				char *xp, *pp = ibuf + 2;
				int n;
				if (akeysz) {	/* insert current time & date */
					time_t rtim = time(0);
					fprintf(rfp, "# %s", ctime(&rtim));
				} else {
					fputs(ibuf, rfp);
					if (strncmp(pp, "AESVS ", 6) == 0) {
						strcpy(algo, "AES");
						/* get test type */
						pp += 6;
						xp = strchr(pp, ' ');
						n = xp - pp;
						strncpy(atest, pp, n);
						atest[n] = '\0';
						/* get mode */
						xp = strrchr(pp, ' ');	/* get mode" */
						n = strlen(xp + 1) - 1;
						strncpy(amode, xp + 1, n);
						amode[n] = '\0';
						/* amode[3] = '\0'; */
						if (VERBOSE)
							printf
							    ("Test = %s, Mode = %s\n",
							     atest, amode);
					} else
					    if (strncasecmp
						(pp, "Key Length : ",
						 13) == 0) {
						akeysz = atoi(pp + 13);
						if (VERBOSE)
							printf
							    ("Key size = %d\n",
							     akeysz);
					}
				}
			}
			break;

		case 1:	/* [ENCRYPT] | [DECRYPT] */
			if (ibuf[0] == '[') {
				fputs(ibuf, rfp);
				++step;
				if (strncasecmp(ibuf, "[ENCRYPT]", 9) == 0)
					dir = 1;
				else if (strncasecmp(ibuf, "[DECRYPT]", 9) == 0)
					dir = 0;
				else {
					printf("Invalid keyword: %s\n", ibuf);
					err = 1;
				}
				break;
			} else if (dir == -1) {
				err = 1;
				printf("Missing ENCRYPT/DECRYPT keyword\n");
				break;
			} else
				step = 2;

		case 2:	/* KEY = xxxx */
			fputs(ibuf, rfp);
			if (*ibuf == '\n' || *ibuf == '\r')
				break;
			if (!strncasecmp(ibuf, "COUNT = ", 8))
				break;

			if (strncasecmp(ibuf, "KEY = ", 6) != 0) {
				printf("Missing KEY\n");
				err = 1;
			} else {
				len = hex2bin((char *)ibuf + 6, aKey);
				if (len < 0) {
					printf("Invalid KEY\n");
					err = 1;
					break;
				}
				PrintValue("KEY", aKey, len);
				if (strcmp(amode, "ECB") == 0) {
					memset(iVec, 0, sizeof(iVec));
					step = (dir) ? 4 : 5;	/* no ivec for ECB */
				} else
					++step;
			}
			break;

		case 3:	/* IV = xxxx */
			fputs(ibuf, rfp);
			if (strncasecmp(ibuf, "IV = ", 5) != 0) {
				printf("Missing IV\n");
				err = 1;
			} else {
				len = hex2bin((char *)ibuf + 5, iVec);
				if (len < 0) {
					printf("Invalid IV\n");
					err = 1;
					break;
				}
				PrintValue("IV", iVec, len);
				step = (dir) ? 4 : 5;
			}
			break;

		case 4:	/* PLAINTEXT = xxxx */
			fputs(ibuf, rfp);
			if (strncasecmp(ibuf, "PLAINTEXT = ", 12) != 0) {
				printf("Missing PLAINTEXT\n");
				err = 1;
			} else {
				int nn = strlen(ibuf + 12);
				len = hex2bin(ibuf + 12, plaintext);
				if (len < 0) {
					printf("Invalid PLAINTEXT: %s",
					       ibuf + 12);
					err = 1;
					break;
				}
				if (len >= sizeof(plaintext)) {
					printf("Buffer overflow\n");
				}
				PrintValue("PLAINTEXT",
					   (unsigned char *)plaintext, len);
				if (strcmp(atest, "MCT") == 0) {	/* Monte Carlo Test */
					if (do_mct(amode, akeysz, aKey, iVec,
						   dir,
						   (unsigned char *)plaintext,
						   len, rfp) < 0)
						EXIT(1);
				} else {
					ret = AESTest(&ctx, amode, akeysz, aKey, iVec, dir,	/* 0 = decrypt, 1 = encrypt */
						      plaintext, ciphertext,
						      len);
					OutputValue("CIPHERTEXT", ciphertext,
						    len, rfp, 0);
				}
				step = 6;
			}
			break;

		case 5:	/* CIPHERTEXT = xxxx */
			fputs(ibuf, rfp);
			if (strncasecmp(ibuf, "CIPHERTEXT = ", 13) != 0) {
				printf("Missing KEY\n");
				err = 1;
			} else {
				len = hex2bin(ibuf + 13, ciphertext);
				if (len < 0) {
					printf("Invalid CIPHERTEXT\n");
					err = 1;
					break;
				}

				PrintValue("CIPHERTEXT", ciphertext, len);
				if (strcmp(atest, "MCT") == 0) {	/* Monte Carlo Test */
					do_mct(amode, akeysz, aKey, iVec,
					       dir, ciphertext, len, rfp);
				} else {
					ret = AESTest(&ctx, amode, akeysz, aKey, iVec, dir,	/* 0 = decrypt, 1 = encrypt */
						      plaintext, ciphertext,
						      len);
					OutputValue("PLAINTEXT",
						    (unsigned char *)plaintext,
						    len, rfp, 0);
				}
				step = 6;
			}
			break;

		case 6:
			if (ibuf[0] != '\n' && ibuf[0] != '\r') {
				err = 1;
				printf("Missing terminator\n");
			} else if (strcmp(atest, "MCT") != 0) {	/* MCT already added terminating nl */
				fputs(ibuf, rfp);
			}
			step = 1;
			break;
		}
	}
	if (rfp)
		fclose(rfp);
	if (afp)
		fclose(afp);
	return err;
}

/*--------------------------------------------------
  Processes either a single file or 
  a set of files whose names are passed in a file.
  A single file is specified as:
    aes_test -f xxx.req
  A set of files is specified as:
    aes_test -d xxxxx.xxx
  The default is: -d req.txt
--------------------------------------------------*/
int main(int argc, char **argv)
{
	char *rqlist = "req.txt", *rspfile = NULL;
	FILE *fp = NULL;
	char fn[250] = "", rfn[256] = "";
	int f_opt = 0, d_opt = 1;

#ifdef REQUIRE_FIPS
	if (!gnutls_fips140_mode_enabled()) {
		do_print_errors();
		EXIT(1);
	}
#endif
	if (argc > 1) {
		if (strcasecmp(argv[1], "-d") == 0) {
			d_opt = 1;
		} else if (strcasecmp(argv[1], "-f") == 0) {
			f_opt = 1;
			d_opt = 0;
		} else {
			printf("Invalid parameter: %s\n", argv[1]);
			return 0;
		}
		if (argc < 3) {
			printf("Missing parameter\n");
			return 0;
		}
		if (d_opt)
			rqlist = argv[2];
		else {
			strcpy(fn, argv[2]);
			rspfile = argv[3];
		}
	}
	if (d_opt) {		/* list of files (directory) */
		if (!(fp = fopen(rqlist, "r"))) {
			printf("Cannot open req list file\n");
			return -1;
		}
		while (fgets(fn, sizeof(fn), fp)) {
			strtok(fn, "\r\n");
			strcpy(rfn, fn);
			if (VERBOSE)
				printf("Processing: %s\n", rfn);
			if (proc_file(rfn, rspfile)) {
				printf(">>> Processing failed for: %s <<<\n",
				       rfn);
				EXIT(1);
			}
		}
		fclose(fp);
	} else {		/* single file */

		if (VERBOSE)
			printf("Processing: %s\n", fn);
		if (proc_file(fn, rspfile)) {
			printf(">>> Processing failed for: %s <<<\n", fn);
		}
	}
	EXIT(0);
	return 0;
}
