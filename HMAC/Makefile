#
# OpenSSL/fips/hmac/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

CC=	gcc
CFLAGS=-g -O2
LDFLAGS=-L/usr/local/lib -lgnutls

all: fips_hmactest

Q=../testvectors/HMAC/req
A=../testvectors/HMAC/resp

.PHONY: check

check: fips_hmactest
	-rm -rf $A
	-mkdir $A
	if [ -f $(Q)/HMAC.req ]; then ./fips_hmactest < $(Q)/HMAC.req > $(A)/HMAC.rsp; fi

clean:
	rm -f *.o *~ fips_hmactest
