#
# OpenSSL/fips/sha/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

CC=	gcc
CFLAGS=-g -O2
LDFLAGS=-L/usr/local/lib -lgnutls

all: fips_shatest

Q=../testvectors/SHA/req
A=../testvectors/SHA/resp

VECTORS = SHA1LongMsg \
	SHA1Monte \
	SHA1ShortMsg \
	SHA224LongMsg \
	SHA224Monte \
	SHA224ShortMsg \
	SHA256LongMsg \
	SHA256Monte \
	SHA256ShortMsg \
	SHA384LongMsg \
	SHA384Monte \
	SHA384ShortMsg \
	SHA512LongMsg \
	SHA512Monte \
	SHA512ShortMsg

.PHONY: check

check: fips_shatest
	-rm -rf $A
	-mkdir $A
	for file in $(VECTORS); do \
	    if [ -f $(Q)/$$file.req ]; then \
		./fips_shatest $(Q)/$$file.req $(A)/$$file.rsp; \
	    fi; \
	done

clean:
	rm -f *.o *~ fips_shatest
