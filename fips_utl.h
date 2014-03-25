/* ====================================================================
 * Copyright (c) 2007 The OpenSSL Project.  All rights reserved.
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

#include <gnutls/gnutls.h>

#define do_print_errors() \
	fprintf(stderr, "Error in %s:%d\n", __FILE__, __LINE__)

int hex2bin(const char *in, unsigned char *out)
{
	int n1, n2;
	unsigned char ch;
	int len = strlen(in);
	
	if (len > 0 && in[len-1] == '\n') {
		len--;
	}

	if (len > 0 && in[len-1] == '\r') {
		len--;
	}
	
	n2 = n1 = 0;
	if (len % 2 != 0) {
		if ((in[n1] >= '0') && (in[n1] <= '9'))
			ch = in[n1++] - '0';
		else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
			ch = in[n1++] - 'A' + 10;
		else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
			ch = in[n1++] - 'a' + 10;
		else {
			fprintf(stderr, "unknown char: '%c'\n", in[n1]);
			return -1;
		}

		out[n2++] = ch;
	}

	for (; in[n1] && in[n1] != '\n' && in[n1] != '\r';) {	/* first byte */
		if ((in[n1] >= '0') && (in[n1] <= '9'))
			ch = in[n1++] - '0';
		else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
			ch = in[n1++] - 'A' + 10;
		else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
			ch = in[n1++] - 'a' + 10;
		else
			return -1;
		if (!in[n1]) {
			out[n2++] = ch;
			break;
		}
		out[n2] = ch << 4;
		/* second byte */
		if ((in[n1] >= '0') && (in[n1] <= '9'))
			ch = in[n1++] - '0';
		else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
			ch = in[n1++] - 'A' + 10;
		else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
			ch = in[n1++] - 'a' + 10;
		else {
			fprintf(stderr, "unknown char: '%c'\n", in[n1]);
			return -1;
		}
		out[n2++] |= ch;
	}
	return n2;
}

unsigned char *hex2bin_m(const char *in, long *plen)
{
	unsigned char *p;
	p = malloc((strlen(in) + 1) / 2);
	*plen = hex2bin(in, p);
	return p;
}

int do_hex2raw(gnutls_datum_t * pr, const char *in)
{
	unsigned char *p;
	long plen;

	p = hex2bin_m(in, &plen);
	if (!p)
		return 0;

	pr->data = p;
	pr->size = plen;

	return 1;
}

int do_raw_print(FILE * out, gnutls_datum_t * bn)
{
unsigned i;

	if (bn->size == 0) {
		fputs("00", out);
		return 1;
	}

	for (i=0;i<bn->size;i++) {
		fprintf(out, "%02x", bn->data[i]);
	
	}
	return 1;
}

int do_bn_print_name(FILE * out, const char *name, gnutls_datum_t * bn)
{
	int r;
	fprintf(out, "%s = ", name);
	r = do_raw_print(out, bn);
	if (!r)
		return 0;
	fputs("\n", out);
	return 1;
}

int parse_line(char **pkw, char **pval, char *linebuf, char *olinebuf)
{
	char *keyword, *value, *p, *q;
	strcpy(linebuf, olinebuf);
	keyword = linebuf;
	/* Skip leading space */
	while (isspace((unsigned char)*keyword))
		keyword++;

	/* Look for = sign */
	p = strchr(linebuf, '=');

	/* If no '=' exit */
	if (!p)
		return 0;

	q = p - 1;

	/* Remove trailing space */
	while (isspace((unsigned char)*q))
		*q-- = 0;

	*p = 0;
	value = p + 1;

	/* Remove leading space from value */
	while (isspace((unsigned char)*value))
		value++;

	/* Remove trailing space from value */
	p = value + strlen(value) - 1;

	while (*p == '\n' || isspace((unsigned char)*p))
		*p-- = 0;

	*pkw = keyword;
	*pval = value;
	return 1;
}

gnutls_datum_t hex2raw(const char *in)
{
	gnutls_datum_t p = {NULL, 0};

	if (!do_hex2raw(&p, in))
		return p;

	return p;
}

int bin2hex(const unsigned char *in, int len, char *out)
{
	int n1, n2;
	unsigned char ch;

	for (n1 = 0, n2 = 0; n1 < len; ++n1) {
		ch = in[n1] >> 4;
		if (ch <= 0x09)
			out[n2++] = ch + '0';
		else
			out[n2++] = ch - 10 + 'a';
		ch = in[n1] & 0x0f;
		if (ch <= 0x09)
			out[n2++] = ch + '0';
		else
			out[n2++] = ch - 10 + 'a';
	}
	out[n2] = '\0';
	return n2;
}

void pv(const char *tag, const unsigned char *val, int len)
{
	char obuf[2048];

	bin2hex(val, len, obuf);
	printf("%s = %s\n", tag, obuf);
}

/* To avoid extensive changes to test program at this stage just convert
 * the input line into an acceptable form. Keyword lines converted to form
 * "keyword = value\n" no matter what white space present, all other lines
 * just have leading and trailing space removed.
 */

int tidy_line(char *linebuf, char *olinebuf)
{
	char *keyword, *value, *p, *q;
	strcpy(linebuf, olinebuf);
	keyword = linebuf;
	/* Skip leading space */
	while (isspace((unsigned char)*keyword))
		keyword++;
	/* Look for = sign */
	p = strchr(linebuf, '=');

	/* If no '=' just chop leading, trailing ws */
	if (!p) {
		p = keyword + strlen(keyword) - 1;
		while (*p == '\n' || isspace((unsigned char)*p))
			*p-- = 0;
		strcpy(olinebuf, keyword);
		strcat(olinebuf, "\n");
		return 1;
	}

	q = p - 1;

	/* Remove trailing space */
	while (isspace((unsigned char)*q))
		*q-- = 0;

	*p = 0;
	value = p + 1;

	/* Remove leading space from value */
	while (isspace((unsigned char)*value))
		value++;

	/* Remove trailing space from value */
	p = value + strlen(value) - 1;

	while (*p == '\n' || isspace((unsigned char)*p))
		*p-- = 0;

	strcpy(olinebuf, keyword);
	strcat(olinebuf, " = ");
	strcat(olinebuf, value);
	strcat(olinebuf, "\n");

	return 1;
}

/* NB: this return the number of _bits_ read */
int bint2bin(const char *in, int len, unsigned char *out)
{
	int n;

	memset(out, 0, len);
	for (n = 0; n < len; ++n)
		if (in[n] == '1')
			out[n / 8] |= (0x80 >> (n % 8));
	return len;
}

int bin2bint(const unsigned char *in, int len, char *out)
{
	int n;

	for (n = 0; n < len; ++n)
		out[n] = (in[n / 8] & (0x80 >> (n % 8))) ? '1' : '0';
	return n;
}

/*-----------------------------------------------*/

void PrintValue(char *tag, unsigned char *val, int len)
{
#if VERBOSE
	char obuf[2048];
	int olen;
	olen = bin2hex(val, len, obuf);
	printf("%s = %.*s\n", tag, olen, obuf);
#endif
}

void OutputValue(char *tag, unsigned char *val, int len, FILE * rfp,
		 int bitmode)
{
	char obuf[2048];
	int olen;

	if (bitmode)
		olen = bin2bint(val, len, obuf);
	else
		olen = bin2hex(val, len, obuf);

	fprintf(rfp, "%s = %.*s\n", tag, olen, obuf);
#if VERBOSE
	printf("%s = %.*s\n", tag, olen, obuf);
#endif
}

#define EXIT(x) exit(x)
