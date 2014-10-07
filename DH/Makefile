#
# OpenSSL/fips/dsa/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

CC=	gcc
CFLAGS=-g -Wall -O2 
LDFLAGS=-L/usr/local/lib -lgnutls -lgmp -lhogweed

all: fips_dhvs

Q=../testvectors/DH/req
A=../testvectors/DH/resp

common: fips_dhvs
	-rm -rf $A
	-mkdir $A

test_dhgen: common
	if [ -f $(Q)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_init.req ]; then ./fips_dhvs dhgen < $(Q)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_init.req > $(A)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_init.rsp; fi

test_dhver: common
	if [ -f $(Q)/KASValidityTest_FFCEphem_NOKC_ZZOnly_init.req ]; then ./fips_dhvs dhver < $(Q)/KASValidityTest_FFCEphem_NOKC_ZZOnly_init.req > $(A)/KASValidityTest_FFCEphem_NOKC_ZZOnly_init.rsp; fi

.PHONY: check common test_dhgen test_dhver

check: test_dhgen test_dhver

clean:
	rm -f *.o *~ fips_dhvs
