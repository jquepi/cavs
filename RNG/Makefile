#
# OpenSSL/fips/rng/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

CC=	gcc
CFLAGS=-g -O2
LDFLAGS=-L/usr/local/lib -lgnutls

all: fips_rngvs

Q=../testvectors/RNG/req
A=../testvectors/RNG/resp

.PHONY: check

check: fips_rngvs
	-rm -rf $A
	-mkdir $A
	if [ -f $(Q)/CTR_DRBG.req ]; then ./fips_rngvs < $(Q)/CTR_DRBG.req > $(A)/CTR_DRBG.rsp; fi

clean:
	rm -f *.o *~ fips_rngvs
