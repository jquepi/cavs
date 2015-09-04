#
# OpenSSL/fips/dsa/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

-include ../common.mk
CC=	gcc
CFLAGS=-g -Wall -O2 
LDFLAGS=$(COMMON_LDFLAGS) -lgnutls -lgmp -lhogweed

all: fips_dhvs

Q=../testvectors/KAS/req
A=../testvectors/KAS/resp

common: fips_dhvs
	-rm -f $A/*Test_FCC*
	-mkdir -p $A

test_dhgen: common
	if [ -f $(Q)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_init.req ]; then ./fips_dhvs dhgen < $(Q)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_init.req > $(A)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_init.rsp; fi
	if [ -f $(Q)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_resp.req ]; then ./fips_dhvs dhgen < $(Q)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_resp.req > $(A)/KASFunctionTest_FFCEphem_NOKC_ZZOnly_resp.rsp; fi

test_dhver: common
	if [ -f $(Q)/KASValidityTest_FFCEphem_NOKC_ZZOnly_init.req ]; then ./fips_dhvs dhver < $(Q)/KASValidityTest_FFCEphem_NOKC_ZZOnly_init.req > $(A)/KASValidityTest_FFCEphem_NOKC_ZZOnly_init.rsp; fi
	if [ -f $(Q)/KASValidityTest_FFCEphem_NOKC_ZZOnly_resp.req ]; then ./fips_dhvs dhver < $(Q)/KASValidityTest_FFCEphem_NOKC_ZZOnly_resp.req > $(A)/KASValidityTest_FFCEphem_NOKC_ZZOnly_resp.rsp; fi

.PHONY: check common test_dhgen test_dhver

check: test_dhgen test_dhver

clean:
	rm -f *.o *~ fips_dhvs
