#
# OpenSSL/fips/dsa/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

export GNUTLS_FORCE_FIPS_MODE = 2
CC=	gcc
CFLAGS=-g -Wall -O2 
LDFLAGS=-L/usr/local/lib -lgnutls -lgmp -lhogweed

all: fips_dssvs

Q=../testvectors/DSA2/req
A=../testvectors/DSA2/resp

common: fips_dssvs
	-rm -rf $A
	-mkdir $A

test_keypair: common
	if [ -f $(Q)/KeyPair.req ]; then ./fips_dssvs keypair < $(Q)/KeyPair.req > $(A)/KeyPair.rsp; fi

test_gen: common
	if [ -f $(Q)/PQGGen.req ]; then ./fips_dssvs pqg < $(Q)/PQGGen.req > $(A)/PQGGen.rsp; fi

test_siggen: common
	if [ -f $(Q)/SigGen.req ]; then ./fips_dssvs siggen < $(Q)/SigGen.req > $(A)/SigGen.rsp; fi

test_sigver: common
	if [ -f $(Q)/SigVer.req ]; then ./fips_dssvs sigver < $(Q)/SigVer.req > $(A)/SigVer.rsp; fi

test_ver: common
	if [ -f $(Q)/PQGVer1863.req ]; then ./fips_dssvs pqgver < $(Q)/PQGVer1863.req > $(A)/PQGVer1863.rsp; fi

.PHONY: check common test_keypair test_gen test_siggen test_sigver test_ver

check: test_keypair test_gen test_siggen test_sigver test_ver
	#if [ -f $(Q)/SigVer.req ]; then ./fips_dssvs sigver < $(Q)/SigVer.req > $(A)/SigVer.rsp; fi

clean:
	rm -f *.o *~ fips_dssvs
