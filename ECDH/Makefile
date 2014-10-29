#
# OpenSSL/fips/dsa/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

export GNUTLS_FORCE_FIPS_MODE = 2
CC=	gcc
CFLAGS=-g -Wall -O2 
LDFLAGS=-L/usr/local/lib -lgnutls -lgmp -lhogweed

all: fips_ecdhvs

Q=../testvectors/KAS/req
A=../testvectors/KAS/resp

common: fips_ecdhvs
	-rm -f $A/*Test_ECC*
	-mkdir -p $A

test_ecdhgen: common
	if [ -f $(Q)/KASFunctionTest_ECCEphemeralUnified_NOKC_ZZOnly_init.req ]; then ./fips_ecdhvs ecdhgen < $(Q)/KASFunctionTest_ECCEphemeralUnified_NOKC_ZZOnly_init.req > $(A)/KASFunctionTest_ECCEphemeralUnified_NOKC_ZZOnly_init.rsp; fi
	if [ -f $(Q)/KASFunctionTest_ECCEphemeralUnified_NOKC_ZZOnly_resp.req ]; then ./fips_ecdhvs ecdhgen < $(Q)/KASFunctionTest_ECCEphemeralUnified_NOKC_ZZOnly_resp.req > $(A)/KASFunctionTest_ECCEphemeralUnified_NOKC_ZZOnly_resp.rsp; fi

test_ecdhver: common
	if [ -f $(Q)/KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.req ]; then ./fips_ecdhvs ecdhver < $(Q)/KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.req > $(A)/KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.rsp; fi
	if [ -f $(Q)/KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_resp.req ]; then ./fips_ecdhvs ecdhver < $(Q)/KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_resp.req > $(A)/KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_resp.rsp; fi

.PHONY: check common test_ecdhgen test_ecdhver

check: test_ecdhgen test_ecdhver

clean:
	rm -f *.o *~ fips_ecdhvs
