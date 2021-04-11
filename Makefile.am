ACLOCAL_AMFLAGS = -I m4

openssl_modulesdir = $(MODULESDIR)
openssl_modules_LTLIBRARIES = tpm2.la

tpm2_la_SOURCES = src/tpm2-provider.c \
                  src/tpm2-provider-core.c \
                  src/tpm2-provider-types.c \
                  src/tpm2-provider-x509.c \
                  src/tpm2-provider-digest.c \
                  src/tpm2-provider-cipher.c \
                  src/tpm2-provider-rand.c \
                  src/tpm2-provider-pkey.c \
                  src/tpm2-provider-store-file.c \
                  src/tpm2-provider-store-object.c \
                  src/tpm2-provider-decoder-der.c \
                  src/tpm2-provider-decoder-tss2.c \
                  src/tpm2-provider-encoder.c \
                  src/tpm2-provider-keymgmt-rsa.c \
                  src/tpm2-provider-keymgmt-ec.c \
                  src/tpm2-provider-keyexch.c \
                  src/tpm2-provider-asymcipher-rsa.c \
                  src/tpm2-provider-signature.c

# https://www.gnu.org/software/autoconf-archive/ax_code_coverage.html
if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
dist-clean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

COMMON_CFLAGS = $(CRYPTO_CFLAGS)
COMMON_LDFLAGS =
if WITH_ASAN
COMMON_CFLAGS += -O1 -g -fsanitize=address -fno-omit-frame-pointer
COMMON_LDFLAGS += -fsanitize=address
endif

tpm2_la_CFLAGS = $(TSS2_ESYS_CFLAGS) $(TSS2_TCTILDR_CFLAGS) $(COMMON_CFLAGS) $(CODE_COVERAGE_CFLAGS)
tpm2_la_LIBADD = $(TSS2_ESYS_LIBS) $(TSS2_TCTILDR_LIBS) $(CODE_COVERAGE_LIBS)
if TSS2_RC
tpm2_la_LIBADD += $(TSS2_RC_LIBS)
endif
tpm2_la_LDFLAGS = -module -avoid-version -no-undefined -export-symbols-regex 'OSSL_provider_init' $(COMMON_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)

check_PROGRAMS = test/selftest
test_selftest_SOURCES = test/selftest.c
test_selftest_CFLAGS = $(COMMON_CFLAGS)
test_selftest_LDADD = $(CRYPTO_LIBS)
test_selftest_LDFLAGS = $(COMMON_LDFLAGS)

TESTS = $(TESTS_SHELL) $(check_PROGRAMS)

TESTS_SHELL = test/list.sh \
              test/digest.sh \
              test/cipher_aes128_ecb.sh \
              test/cipher_aes128_cbc.sh \
              test/cipher_aes256.sh \
              test/cipher_aes256_nopad.sh \
              test/cipher_camellia128.sh \
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
              test/rsapss_genpkey_sign_rawin.sh \
              test/rsapss_createak_tls_server.sh \
              test/ec_genpkey_check.sh \
              test/ec_genpkey_parameters.sh \
              test/ecdsa_genpkey_auth.sh \
              test/ecdsa_genpkey_sign_rawin.sh \
              test/ecdsa_createak_sign_handle.sh \
              test/ecdh_genpkey_keyexch.sh \
              test/ec_createak_x509_csr.sh \
              test/ec_genpkey_tls_server.sh \
              test/store_errors.sh

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(srcdir)/test/run
