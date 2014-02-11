#
# OpenSSL/fips/aes/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

CC=	gcc
CFLAGS=-g -O2
LDFLAGS=-L/usr/local/lib -lgnutls

all: fips_aesavs fips_gcmtest

Q=../testvectors/AES/req
A=../testvectors/AES/resp

check: aes_test aes_gcm_test

.PHONY: aes_test aes_gcm_test check

aes_test: fips_aesavs
	-find $Q -name '*.req' > testlist
	-rm -rf $A
	-mkdir $A
	if [ -s testlist ]; then ./fips_aesavs -d testlist; fi

GCM_Q=../testvectors/AES_GCM/req
GCM_A=../testvectors/AES_GCM/resp

aes_gcm_test: fips_gcmtest
	-rm -rf $(GCM_A)
	-mkdir $(GCM_A)
	-ls $(GCM_Q)/|grep ^gcmEncrypt > testlist.gcm
	for i in `cat testlist.gcm`;do \
		./fips_gcmtest -encryptIVext $(GCM_Q)/$$i $(GCM_A)/$$i; \
		done
	-ls $(GCM_Q)/|grep ^gcmDecrypt > testlist.gcm
	for i in `cat testlist.gcm`;do \
		./fips_gcmtest -decrypt $(GCM_Q)/$$i $(GCM_A)/$$i; \
		done

clean:
	rm -f *.o *~ fips_aesavs fips_gcmtest
