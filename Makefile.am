ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = tpm2.la

tpm2_la_SOURCES = src/tpm2-provider.c \
                  src/tpm2-provider-core.c \
                  src/tpm2-provider-pkey.c \
                  src/tpm2-provider-store-handle.c \
                  src/tpm2-provider-rand.c \
                  src/tpm2-provider-rsa-asymcipher.c \
                  src/tpm2-provider-rsa-decoder.c \
                  src/tpm2-provider-rsa-encoder.c \
                  src/tpm2-provider-rsa-keymgmt.c \
                  src/tpm2-provider-rsa-signature.c

tpm2_la_CFLAGS = $(TSS2_ESYS_CFLAGS) $(TSS2_TCTILDR_CFLAGS) $(CRYPTO_CFLAGS)
tpm2_la_LIBADD = $(TSS2_ESYS_LIBS) $(TSS2_TCTILDR_LIBS)
if TSS2_RC
tpm2_la_LIBADD += $(TSS2_RC_LIBS)
endif
tpm2_la_LDFLAGS = -module -avoid-version -no-undefined -export-symbols-regex 'OSSL_provider_init'

TESTS = $(TESTS_SHELL)

TESTS_SHELL = test/list.sh \
              test/rand.sh \
              test/rsa_genrsa_check.sh \
              test/rsa_genpkey_sign.sh \
              test/rsa_createak_sign.sh \
              test/rsa_create_decrypt.sh

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(srcdir)/test/run
