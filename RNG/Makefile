#
# OpenSSL/fips/rng/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

-include ../common.mk
CC=	gcc
CFLAGS=-g -O2
LDFLAGS=$(COMMON_LDFLAGS) -lgnutls

all: fips_rngvs

Q=../testvectors/DRBG800-90A/req
A=../testvectors/DRBG800-90A/resp

.PHONY: check

check: fips_rngvs
	-rm -rf $A
	-mkdir $A
	if [ -f $(Q)/CTR_DRBG.req ]; then ./fips_rngvs < $(Q)/CTR_DRBG.req > $(A)/CTR_DRBG.rsp; fi

clean:
	rm -f *.o *~ fips_rngvs
