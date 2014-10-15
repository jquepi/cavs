/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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
  NIST DES Modes of Operation Validation System
  Test Program

  Based on the AES Validation Suite, which was:
  Donated to OpenSSL by:
  V-ONE Corporation
  20250 Century Blvd, Suite 300
  Germantown, MD 20874
  U.S.A.
  ----------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "fips_utl.h"

#define DES_BLOCK_SIZE 8

#define VERBOSE 0

int DESTest(gnutls_cipher_hd_t * ctx, char *amode, int akeysz, unsigned char *aKey, unsigned char *iVec, int dir,	/* 0 = decrypt, 1 = encrypt */
	    unsigned char *out, unsigned char *in, int len)
{
	gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_UNKNOWN;
	gnutls_datum_t key;
	gnutls_datum_t iv;
	int ret;

	if (akeysz != 192) {
		printf("Invalid key size: %d\n", akeysz);
		EXIT(1);
	}

	if (strcasecmp(amode, "CBC") == 0)
		cipher = GNUTLS_CIPHER_3DES_CBC;
	else {
		printf("Unknown mode: %s\n", amode);
		EXIT(1);
	}
	
	key.size = 24;
	key.data = aKey;

	iv.size = 8;
	iv.data = iVec;

	ret = gnutls_cipher_init(ctx, cipher, &key, &iv);
	if (ret < 0) {
		do_print_errors();
		return 0;
	}
	
	if (dir == 0)
		ret = gnutls_cipher_decrypt2(*ctx, in, len, out, len);
	else
		ret = gnutls_cipher_encrypt2(*ctx, in, len, out, len);
	if (ret < 0) {
		do_print_errors();
		return 0;
	}

	return 1;
}

void DebugValue(char *tag, unsigned char *val, int len)
{
	char obuf[2048];
	int olen;
	olen = bin2hex(val, len, obuf);
	printf("%s = %.*s\n", tag, olen, obuf);
}

void shiftin(unsigned char *dst, unsigned char *src, int nbits)
{
	int n;

	/* move the bytes... */
	memmove(dst, dst + nbits / 8, 3 * 8 - nbits / 8);
	/* append new data */
	memcpy(dst + 3 * 8 - nbits / 8, src, (nbits + 7) / 8);
	/* left shift the bits */
	if (nbits % 8)
		for (n = 0; n < 3 * 8; ++n)
			dst[n] =
			    (dst[n] << (nbits % 8)) | (dst[n + 1] >>
						       (8 - nbits % 8));
}

/*-----------------------------------------------*/
static const unsigned char odd_parity[256]={
  1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254};

static
void DES_set_odd_parity(uint8_t *key)
{
	unsigned int i;

	for (i=0; i<8; i++)
		key[i]=odd_parity[key[i]];
}

#define T_MODES 1
char *t_tag[2] = { "PLAINTEXT", "CIPHERTEXT" };
char *t_mode[T_MODES] = { "CBC", };
enum Mode { CBC };
int Sizes[T_MODES] = { 64 };

void do_mct(char *amode,
	    int akeysz, int numkeys, unsigned char *akey, unsigned char *ivec,
	    int dir, unsigned char *text, int len, FILE * rfp)
{
	int i, imode, ret;
	unsigned n;
	unsigned char nk[4 * 8];	/* longest key+8 */
	unsigned char text0[8];

	for (imode = 0; imode < T_MODES; ++imode) {
		if (!strcmp(amode, t_mode[imode]))
			break;
	}

	if (imode == 6) {
		printf("Unrecognized mode: %s\n", amode);
		EXIT(1);
	}

	for (i = 0; i < 400; ++i) {
		int j;
		int n;
		int kp = akeysz / 64;
		unsigned char old_iv[8];
		unsigned char old_text[8];
		unsigned char ct[8];
		gnutls_cipher_hd_t ctx = NULL;

		fprintf(rfp, "\nCOUNT = %d\n", i);
		if (kp == 1)
			OutputValue("KEY", akey, 8, rfp, 0);
		else {
			for (n = 0; n < kp; ++n) {
				fprintf(rfp, "KEY%d", n + 1);
				OutputValue("", akey + n * 8, 8, rfp, 0);
			}
		}

		OutputValue("IV", ivec, 8, rfp, 0);
		OutputValue(t_tag[dir ^ 1], text, len, rfp, 0);

#if 0
		/* compensate for endianness */
		if (imode == CFB1)
			text[0] <<= 7;
#endif

		memcpy(text0, text, 8);

		for (j = 0; j < 10000; ++j) {
			memcpy(old_text, text, 8);
			if (j == 0) {
				if (ctx != NULL)
					gnutls_cipher_deinit(ctx);

				memcpy(old_iv,ivec,8);
				
				if (dir == 0)
					memcpy(ct, &text[len-8], 8);
				DESTest(&ctx, amode, akeysz, akey, ivec, dir,
					text, text, len);
				if (dir != 0)
					memcpy(ct, &text[len-8], 8);
			} else {
				memcpy(old_iv, ct, 8);

				if (dir == 0) {
					memcpy(ct, &text[len-8], 8);
					ret = gnutls_cipher_decrypt2(ctx, text, len, text, len);
				} else {
					ret = gnutls_cipher_encrypt2(ctx, text, len, text, len);
					memcpy(ct, &text[len-8], 8);
				}
				if (ret < 0) {
					do_print_errors();
					exit(1);
				}
			}
			if (j == 9999) {
				OutputValue(t_tag[dir], text, len, rfp, 0);
				              /*memcpy(ivec,text,8);*/
			}
			/*      DebugValue("iv",ctx.iv,8); */
			/* accumulate material for the next key */
			shiftin(nk, text, Sizes[imode]);
			/*      DebugValue("nk",nk,24); */
			if (dir && imode == CBC)
				memcpy(text, old_iv, 8);
		}

		for (n = 0; n < 8; ++n)
			akey[n] ^= nk[16 + n];
		for (n = 0; n < 8; ++n)
			akey[8 + n] ^= nk[8 + n];
		for (n = 0; n < 8; ++n)
			akey[16 + n] ^= nk[n];
		if (numkeys < 3)
			memcpy(&akey[2 * 8], akey, 8);
		if (numkeys < 2)
			memcpy(&akey[8], akey, 8);
		DES_set_odd_parity(akey);
		DES_set_odd_parity(akey + 8);
		DES_set_odd_parity(akey + 16);

		memcpy(ivec, ct, 8);
	}
}

int proc_file(char *rqfile, char *rspfile)
{
	char afn[256], rfn[256];
	FILE *afp = NULL, *rfp = NULL;
	char ibuf[2048], tbuf[2048];
	int ilen, len, ret = 0;
	char amode[8] = "";
	char atest[100] = "";
	int akeysz = 0;
	unsigned char iVec[20], aKey[40];
	int dir = -1, err = 0, step = 0;
	unsigned char plaintext[2048];
	unsigned char ciphertext[2048];
	char *rp;
	gnutls_cipher_hd_t ctx = NULL;
	int numkeys = 1, start_print = 0;

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
#ifdef OPENSSL_SYS_WIN32
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
		if (step == 3 && !strcmp(amode, "ECB")) {
			memset(iVec, 0, sizeof(iVec));
			step = (dir) ? 4 : 5;	/* no ivec for ECB */
		}
		switch (step) {
		case 0:	/* read preamble */
			if (ibuf[0] == '\n' || ibuf[0] == '\r') {	/* end of preamble */
				if (*amode == '\0') {
					printf("Missing Mode\n");
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
				if (*amode) {	/* insert current time & date */
					time_t rtim = time(0);
					fprintf(rfp, "# %s", ctime(&rtim));
				} else {
					fputs(ibuf, rfp);
					if (!strncmp(pp, "INVERSE ", 8)
					    || !strncmp(pp, "DES ", 4)
					    || !strncmp(pp, "TDES ", 5)
					    || !strncmp(pp, "PERMUTATION ", 12)
					    || !strncmp(pp, "SUBSTITUTION ", 13)
					    || !strncmp(pp, "VARIABLE ", 9)) {
						/* get test type */
						if (!strncmp(pp, "DES ", 4))
							pp += 4;
						else if (!strncmp
							 (pp, "TDES ", 5))
							pp += 5;
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
							    ("Test=%s, Mode=%s\n",
							     atest, amode);
					}
				}
			}
			break;

		case 1:	/* [ENCRYPT] | [DECRYPT] */
			if (ibuf[0] == '\n' || ibuf[0] == '\r')
				break;
			if (ibuf[0] == '[') {
				fputs(ibuf, rfp);
				++step;
				start_print = 0;
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
			if (*ibuf == '\n' || *ibuf == '\r') {
				if (start_print != 0)
					fputs(ibuf, rfp);
				break;
			}

			if (!strncasecmp(ibuf, "COUNT = ", 8)) {
				fputs(ibuf, rfp);
				start_print = 1;
				break;
			}
			if (!strncasecmp(ibuf, "COUNT=", 6)) {
				fputs(ibuf, rfp);
				start_print = 1;
				break;
			}
			if (!strncasecmp(ibuf, "NumKeys = ", 10)) {
				numkeys = atoi(ibuf + 10);
				break;
			}

			if (start_print != 0)
				fputs(ibuf, rfp);
			if (!strncasecmp(ibuf, "KEY = ", 6)) {
				akeysz = 64;
				len = hex2bin((char *)ibuf + 6, aKey);
				if (len < 0) {
					printf("Invalid KEY\n");
					err = 1;
					break;
				}
				PrintValue("KEY", aKey, len);
				++step;
			} else if (!strncasecmp(ibuf, "KEYs = ", 7)) {
				akeysz = 64 * 3;
				len = hex2bin(ibuf + 7, aKey);
				if (len != 8) {
					printf("Invalid KEY\n");
					err = 1;
					break;
				}
				memcpy(aKey + 8, aKey, 8);
				memcpy(aKey + 16, aKey, 8);
				ibuf[4] = '\0';
				PrintValue("KEYs", aKey, len);
				++step;
			} else if (!strncasecmp(ibuf, "KEY", 3)) {
				int n = ibuf[3] - '1';

				akeysz = 64 * 3;
				len = hex2bin(ibuf + 7, aKey + n * 8);
				if (len != 8) {
					printf("Invalid KEY\n");
					err = 1;
					break;
				}
				ibuf[4] = '\0';
				PrintValue(ibuf, aKey, len);
				if (n == 2)
					++step;
			} else {
				printf("Missing KEY\n");
				err = 1;
			}
			break;

		case 3:	/* IV = xxxx */
			if (start_print != 0)
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
			if (start_print != 0)
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
				if (strcmp(atest, "Monte") == 0) {	/* Monte Carlo Test */
					do_mct(amode, akeysz, numkeys, aKey,
					       iVec, dir, plaintext, len, rfp);
				} else {
					assert(dir == 1);
					ret = DESTest(&ctx, amode, akeysz, aKey, iVec, dir,	/* 0 = decrypt, 1 = encrypt */
						      ciphertext, plaintext,
						      len);
					OutputValue("CIPHERTEXT", ciphertext,
						    len, rfp, 0);
				}
				step = 6;
			}
			break;

		case 5:	/* CIPHERTEXT = xxxx */
			if (start_print != 0)
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
				if (strcmp(atest, "Monte") == 0) {	/* Monte Carlo Test */
					do_mct(amode, akeysz, numkeys, aKey,
					       iVec, dir, ciphertext, len, rfp);
				} else {
					assert(dir == 0);
					ret = DESTest(&ctx, amode, akeysz, aKey, iVec, dir,	/* 0 = decrypt, 1 = encrypt */
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

#ifdef OPENSSL_FIPS
	if (!FIPS_mode_set(1)) {
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
