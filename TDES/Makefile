#
# OpenSSL/fips/des/Makefile
#
CPPFLAGS=-I.. $(INCLUDES)
ifeq (${REQUIRE_FIPS},1)
	CPPFLAGS += -DREQUIRE_FIPS=$(REQUIRE_FIPS)
endif

-include ../common.mk
CC=	gcc
CFLAGS=-g -O2
LDFLAGS=$(COMMON_LDFLAGS) -lgnutls

all: fips_desmovs

Q=../testvectors/TDES/req
A=../testvectors/TDES/resp
FAX=../testvectors/TDES/fax

.PHONY: check

check: fips_desmovs
	@-find $Q -name '*.req' > testlist
	@-rm -rf $A
	@-mkdir $A
	@if [ -s testlist ]; then ./fips_desmovs -d testlist; fi
	@for i in `cat testlist`;do \
		base=`basename $$i`; \
		faxfile=`echo $$base | sed 's/\(.*\.\)req/\1fax/'`; \
		respfile=`echo $$base | sed 's/\(.*\.\)req/\1rsp/'`; \
		if test -f $(FAX)/$$faxfile;then \
			echo "Checking against fax: $$faxfile"; \
			cat $(FAX)/$$faxfile|grep -v ^\# > tmpfile; \
			cat $(A)/$$respfile|grep -v ^\# > tmpfile2; \
			diff -B -w -u tmpfile tmpfile2 || exit 1; \
		fi; \
		done
	@rm -f tmpfile tmpfile2

clean:
	rm -f *.o *~ fips_desmovs
