m4_define([version_current], [0])
m4_define([version_revision], [0])
m4_define([version_age], [0])

AC_INIT([libmmap], [version_current.version_revision.version_age])

AC_CONFIG_HEADERS([mmap/config.h])
AC_CONFIG_SRCDIR([./])

AC_CONFIG_AUX_DIR([build/autoconf])
AC_CONFIG_MACRO_DIR([build/autoconf])
AM_INIT_AUTOMAKE([subdir-objects])

LIBMMAP_VERSION=version_current:version_revision:version_age
AC_SUBST(LIBMMAP_VERSION)

AM_PROG_AR
AC_PROG_LIBTOOL
AC_PROG_CC_C99

AS_IF([test "$ac_cv_prog_cc_c99" = "no"], AC_MSG_ERROR([C99 support is required but not found.]))

AC_ARG_ENABLE(debug,
[AS_HELP_STRING([--enable-debug], [enable debugging])],
[], [enable_debug=yes])

AC_ARG_WITH(gghlite,
  [AS_HELP_STRING([--without-gghlite], [disable gghlite support])],
  [], [with_gghlite=yes])
LIBGGHLITE=
AS_IF([test "x$with_gghlite" != xno],
  [AC_SEARCH_LIBS(gghlite_init, gghlite,
    [AC_DEFINE([HAVE_LIBGGHLITE], [1], [Define if you have libgghlite])],
    [AC_MSG_FAILURE([gghlite test failed (--without-gghlite to disable)])])
   AC_SEARCH_LIBS(_fmpz_clear_mpz, flint, [], AC_MSG_ERROR([libflint not found]))
   AC_SEARCH_LIBS(fmpz_modp_matrix_inverse, oz, [], AC_MSG_ERROR([liboz not found]))
  ]
)
AM_CONDITIONAL(HAVE_LIBGGHLITE, test "x$HAVE_LIBGGHLITE" != x1)

AC_CHECK_HEADERS([omp.h])

CFLAGS=                         dnl get rid of default -g -O2
MY_CFLAGS="-Wall -Wformat -Wformat-security -Wextra -Wunused \
-Wshadow -Wmissing-prototypes -Wfloat-equal -Wpointer-arith -Wcast-align \
-Wstrict-prototypes -Wredundant-decls -Wendif-labels -Wcast-qual \
-std=gnu11 -Wpedantic"

if test "x$enable_debug" = x"yes"; then
  MY_CFLAGS+=" -O0 -g"
else
  MY_CFLAGS+=" -O3"
  AC_DEFINE(NDEBUG,1,[Define whether debugging is enabled])
fi
AC_SUBST(MY_CFLAGS)

AX_VALGRIND_CHECK()

AC_SEARCH_LIBS(aes_randinit,aesrand, [], AC_MSG_ERROR([libaesrand not found]))
AC_SEARCH_LIBS(__gmpz_init, gmp, [], AC_MSG_ERROR([libgmp not found]))
AC_SEARCH_LIBS(clt_state_new, clt13, [], AC_MSG_ERROR([libclt13 not found]))

AC_CONFIG_FILES([Makefile mmap/Makefile tests/Makefile])

AC_OUTPUT
