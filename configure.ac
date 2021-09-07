AC_PREREQ([2.69])

AC_INIT([tpm2-openssl],
        [m4_esyscmd_s([git describe --tags --always --dirty])],
        [https://github.com/tpm2-software/tpm2-openssl/issues],
        [],
        [https://github.com/tpm2-software/tpm2-openssl])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/tpm2-provider.c])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Wno-portability])
# enable "silent-rules" option by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])

AC_CANONICAL_HOST

AX_IS_RELEASE([dash-version])
AX_CHECK_ENABLE_DEBUG([info])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_C_BIGENDIAN
LT_INIT([disable-static])

AC_ARG_ENABLE([op-digest],
    AS_HELP_STRING([--disable-op-digest], [Disable digest operations]))
AM_CONDITIONAL(WITH_OP_DIGEST, test "x$enable_op_digest" != "xno")
AS_IF([test "x$enable_op_digest" != "xno"], [AC_DEFINE([WITH_OP_DIGEST])])

AC_ARG_ENABLE([op-cipher],
    AS_HELP_STRING([--disable-op-cipher], [Disable symmetric cipher operations]))
AM_CONDITIONAL(WITH_OP_CIPHER, test "x$enable_op_cipher" != "xno")
AS_IF([test "x$enable_op_cipher" != "xno"], [AC_DEFINE([WITH_OP_CIPHER])])

AC_ARG_ENABLE([asan],
    AS_HELP_STRING([--enable-asan], [Enable asan build, useful for testing]))
AM_CONDITIONAL(WITH_ASAN, test "x$enable_asan" = "xyes")

AC_ARG_ENABLE([tss2-rc],
    AS_HELP_STRING([--disable-tss2-rc], [Disable verbose TSS2 return code reporting]))
AM_CONDITIONAL(TSS2_RC, test "x$enable_tss2_rc" != "xno")

AC_ARG_WITH([modulesdir],
    AS_HELP_STRING([--with-modulesdir=PATH], [Set the directory with OpenSSL modules]))

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 3.0.0],
                  [ac_cryptolibdir=`$PKG_CONFIG --variable=libdir libcrypto`])
AS_IF([test -z "$with_modulesdir"],
      [with_modulesdir=$ac_cryptolibdir/ossl-modules])
AC_SUBST(MODULESDIR, "$with_modulesdir")

PKG_CHECK_MODULES([TSS2_ESYS], [tss2-esys >= 3.0.0],
                  [AC_DEFINE([HAVE_TSS2_ESYS3], [1], [found tss2-esys 3.0.0 or above])],
                  [PKG_CHECK_MODULES([TSS2_ESYS], [tss2-esys >= 2.3.0])])
PKG_CHECK_MODULES([TSS2_TCTILDR], [tss2-tctildr])
AS_IF([test "x$enable_tss2_rc" != "xno"], [
    PKG_CHECK_MODULES([TSS2_RC], [tss2-rc >= 2.3])
    AC_DEFINE(WITH_TSS2_RC)
    ])

AC_SEARCH_LIBS([cbrt], [m])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
