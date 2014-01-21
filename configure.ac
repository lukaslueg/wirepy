AC_PREREQ(2.60)
AC_INIT(wirepy, 0.1)

AC_LANG(C)
AC_PROG_CC

# required to read va_list
AC_FUNC_ALLOCA()

AC_CHECK_HEADERS([stdarg.h])

# Check for wireshark
PKG_CHECK_MODULES([DEPS], [wireshark >= 1.10 glib-2.0 >= 2.16])
CFLAGS="$CFLAGS $DEPS_CFLAGS"
CPPFLAGS="$CPPFLAGS $DEPS_CFLAGS"
LDFLAGS="$LDFLAGS $DEPS_LIBS"

# Check glib2
AC_CHECK_HEADERS([glib.h],
                 [],
                 [AC_MSG_ERROR(["Glib2 headers not found. Check config.log"])])

# g[u]int64 are already defined as "long" instead of "long long" on 64bit
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([gint64], [], [[#include <glib.h>]])
case $ac_cv_sizeof_gint64 in
	$ac_cv_sizeof_long) GINT64TYPE="long";;
	$ac_cv_sizeof_long_long) GINT64TYPE="long long";;
esac
if test -z "$GINT64TYPE"; then
	AC_MSG_ERROR([Failed to detect size of gint64])
fi
AC_SUBST([GINT64TYPE])

# Check wireshark
AC_CHECK_HEADERS([config.h],
                 [],
                 [AC_MSG_ERROR(["Wireshark's config.h not found. Check config.log"])])
AC_CHECK_HEADERS([wiretap/wtap.h register.h epan/epan.h \
                  epan/ipv4.h epan/ipv6-utils.h epan/guid-utils.h epan/tvbuff.h \
                  epan/nstime.h epan/dfilter/drange.h epan/ftypes/ftypes.h \
                  epan/proto.h wsutil/privileges.h epan/prefs.h],
                  [],
                  [AC_MSG_ERROR(['Wireshark headers not found. Check config.log'])],
                  [[#ifdef HAVE_STDARG_H
                    #include <stdarg.h>
                     #endif
                    #ifdef HAVE_GLIB_H
                     #include <glib.h>
                    #endif
                    #ifdef HAVE_CONFIG_H
                     #include <config.h>
                    #endif
                  ]])
AC_SUBST([DEPS_CFLAGS])

# Check wireshark libraries
AC_CHECK_LIB(wireshark, epan_get_version,
             [],
             [AC_MSG_ERROR(['Wireshark libraries not found. Check config.log'])])
AC_CHECK_LIB(wiretap, wtap_read,
             [],
             [AC_MSG_ERROR(['Wiretap was not found. Check config.log'])])
AC_CHECK_LIB(wsutil, init_process_policies,
             [],
             [AC_MSG_ERROR(['WSUtil was not found. Check config.log'])])
AC_SUBST([DEPS_LIBS])

AC_CONFIG_FILES([wirepy/platform.py])

AC_MSG_RESULT([
 ##########################################
 # Building with following configuration
 #  CFLAGS: $DEPS_CFLAGS
 #  LIBS: $DEPS_LIBS
 ##########################################
])

AC_OUTPUT()
