#
# OpenSSL/fips/rsa/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

CC=	gcc
CFLAGS=-g -O2
LDFLAGS=-L/usr/local/lib -lhogweed -lgmp -lgnutls

all: fips_rsavtest

Q=../testvectors/RSA/req
A=../testvectors/RSA/resp

.PHONY: check common test_keypair

common: fips_rsavtest
	-rm -rf $A
	-mkdir $A

test_keypair: common
	if [ -f $(Q)/KeyPair.req ]; then ./fips_rsavtest keypair < $(Q)/KeyPair.req > $(A)/KeyPair.rsp; fi

clean:
	rm -f *.o *~ fips_rsavtest
