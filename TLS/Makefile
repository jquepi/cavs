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

all: fips_tlsvs

Q=../testvectors/TLS/req
A=../testvectors/TLS/resp

.PHONY: check

check: fips_tlsvs
	-rm -rf $A
	-mkdir $A
	if [ -f $(Q)/tls.req ]; then ./fips_tlsvs < $(Q)/tls.req > $(A)/tls.rsp; fi

clean:
	rm -f *.o *~ fips_tlsvs
