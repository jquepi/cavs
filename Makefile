REQUIRE_FIPS=
SUBDIRS=TLS RNG AES TDES HMAC SHA DSA2 ECDSA DH ECDH RSA

export GNUTLS_FORCE_FIPS_MODE = 2

all: check

.PHONY: check $(SUBDIRS)

check: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) $(MAKEFLAGS) -e REQUIRE_FIPS=$(REQUIRE_FIPS) -C $@ check

clean:
	for i in $(SUBDIRS);do $(MAKE) -C $$i clean;done
