#
# OpenSSL/fips/des/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

CC=	gcc
CFLAGS=-g -O2
LDFLAGS=-L/usr/local/lib -lgnutls

all: fips_desmovs

Q=../testvectors/TDES/req
A=../testvectors/TDES/resp

.PHONY: check

check: fips_desmovs
	-find $Q -name '*.req' > testlist
	-rm -rf $A
	-mkdir $A
	if [ -s testlist ]; then ./fips_desmovs -d testlist; fi

clean:
	rm -f *.o *~ fips_desmovs
