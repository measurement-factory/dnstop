#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_CONFIG_SRCDIR([known_tlds.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([ncurses], [initscr])
if test "$ac_cv_lib_ncurses_initscr" != "yes" ; then
AC_CHECK_LIB([curses], [initscr])
fi
AC_CHECK_LIB([pcap], [pcap_open_live])
AC_CHECK_LIB([socket], [main])
AC_CHECK_LIB([nsl], [main])
AC_CHECK_LIB([resolv], [main])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS([endian.h])
AC_CHECK_HEADERS([arpa/nameser_compat.h])
AC_CHECK_HEADERS([net/if_arp.h net/if.h netinet/if_ether.h], [], [],
AC_INCLUDES_DEFAULT
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
])
AC_CHECK_HEADERS([net/if_ppp.h], [], [],
AC_INCLUDES_DEFAULT
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

AC_CHECK_TYPES([struct bpf_timeval], [], [], [
AC_INCLUDES_DEFAULT
#include <pcap.h>
])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([memset select strchr strdup strrchr strstr])

OPTFLAGS=''

AC_ARG_ENABLE(ipv6,
	AS_HELP_STRING([--disable-ipv6], [Enable IPv6 support @<:@default=yes@:>@]),
	[ if test "$enableval" = "no" ; then enable_ipv6=no ; else enable_ipv6=yes ; fi ],
	[ enable_ipv6=yes ])
if test "$enable_ipv6" = "yes" ; then
	AC_SUBST(OPTFLAGS, ["$OPTFLAGS -DUSE_IPV6=1"])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
