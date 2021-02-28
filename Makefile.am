ACLOCAL_AMFLAGS = -I m4

openssl_modulesdir = $(MODULESDIR)
openssl_modules_LTLIBRARIES = tpm2.la

tpm2_la_SOURCES = src/tpm2-provider.c \
                  src/tpm2-provider-algorithms.c \
                  src/tpm2-provider-core.c \
                  src/tpm2-provider-digest.c \
                  src/tpm2-provider-cipher.c \
                  src/tpm2-provider-rand.c \
                  src/tpm2-provider-pkey.c \
                  src/tpm2-provider-store-file.c \
                  src/tpm2-provider-store-object.c \
                  src/tpm2-provider-decoder-der.c \
                  src/tpm2-provider-decoder-tss2.c \
                  src/tpm2-provider-rsa-asymcipher.c \
                  src/tpm2-provider-rsa-encoder.c \
                  src/tpm2-provider-rsa-keymgmt.c \
                  src/tpm2-provider-rsa-signature.c

# https://www.gnu.org/software/autoconf-archive/ax_code_coverage.html
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
dist-clean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

tpm2_la_CFLAGS = $(TSS2_ESYS_CFLAGS) $(TSS2_TCTILDR_CFLAGS) $(CRYPTO_CFLAGS) $(CODE_COVERAGE_CFLAGS)
tpm2_la_LIBADD = $(TSS2_ESYS_LIBS) $(TSS2_TCTILDR_LIBS) $(CODE_COVERAGE_LIBS)
if TSS2_RC
tpm2_la_LIBADD += $(TSS2_RC_LIBS)
endif
tpm2_la_LDFLAGS = -module -avoid-version -no-undefined -export-symbols-regex 'OSSL_provider_init' $(CODE_COVERAGE_LDFLAGS)

check_PROGRAMS = test/selftest
test_selftest_SOURCES = test/selftest.c
test_selftest_CFLAGS = $(CRYPTO_CFLAGS)
test_selftest_LDADD = $(CRYPTO_LIBS)

TESTS = $(TESTS_SHELL) $(check_PROGRAMS)

TESTS_SHELL = test/list.sh \
              test/digest.sh \
              test/cipher_aes128.sh \
              test/cipher_aes256_nopad.sh \
              test/rand.sh \
              test/rsa_genrsa_check.sh \
              test/rsa_genpkey_sign.sh \
              test/rsa_genpkey_sign_rawin.sh \
              test/rsa_genpkey_auth_parent.sh \
              test/rsa_createak_auth.sh \
              test/rsa_createak_sign_object.sh \
              test/rsa_createak_sign_handle.sh \
              test/rsa_create_decrypt.sh \
              test/rsa_genpkey_x509_cert.sh \
              test/rsa_genpkey_tls_server.sh \
              test/rsa_createak_x509_csr.sh \
              test/rsa_createak_tls_server.sh

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(srcdir)/test/run
