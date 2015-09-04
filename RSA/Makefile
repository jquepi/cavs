#
# OpenSSL/fips/rsa/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

-include ../common.mk
CC=	gcc
CFLAGS=-g -O2 -Wall
LDFLAGS=$(COMMON_LDFLAGS) -lhogweed -lgmp -lgnutls

all: fips_rsavtest

Q=../testvectors/RSA2/req
A=../testvectors/RSA2/resp

.PHONY: check common test_keypair

common: fips_rsavtest
	-rm -rf $A
	-mkdir $A

test_keygen: common
	if [ -f $(Q)/KeyGen_186-3.req ]; then ./fips_rsavtest keygen < $(Q)/KeyGen_186-3.req > $(A)/KeyGen_186-3.rsp; fi

test_siggen: common
	if [ -f $(Q)/SigGen15_186-3.req ]; then ./fips_rsavtest siggen < $(Q)/SigGen15_186-3.req > $(A)/SigGen15_186-3.rsp; fi

test_sigver: common
	if [ -f $(Q)/SigVer15_186-3.req ]; then ./fips_rsavtest sigver < $(Q)/SigVer15_186-3.req > $(A)/SigVer15_186-3.rsp; fi

check: test_keygen test_siggen test_sigver

clean:
	rm -f *.o *~ fips_rsavtest
