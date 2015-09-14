#
# OpenSSL/fips/dsa/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

-include ../common.mk
CC=	gcc
CFLAGS=$(COMMON_CFLAGS) -g -Wall -O2 
LDFLAGS=$(COMMON_LDFLAGS) -lgnutls -lgmp -lhogweed

all: fips_ecdsavs

Q=../testvectors/ECDSA2/req
A=../testvectors/ECDSA2/resp

common: fips_ecdsavs
	-rm -rf $A
	-mkdir $A

test_keypair: common
	if [ -f $(Q)/KeyPair.req ]; then ./fips_ecdsavs keypair < $(Q)/KeyPair.req > $(A)/KeyPair.rsp; fi

test_pkval: common
	if [ -f $(Q)/PKV.req ]; then ./fips_ecdsavs pkv < $(Q)/PKV.req > $(A)/PKV.rsp; fi

test_siggen: common
	if [ -f $(Q)/SigGen.req ]; then ./fips_ecdsavs siggen < $(Q)/SigGen.req > $(A)/SigGen.rsp; fi

test_sigver: common
	if [ -f $(Q)/SigVer.req ]; then ./fips_ecdsavs sigver < $(Q)/SigVer.req > $(A)/SigVer.rsp; fi

.PHONY: check common test_siggen test_sigver test_pkval test_keypair

check: test_keypair test_pkval test_siggen test_sigver

clean:
	rm -f *.o *~ fips_ecdsavs
