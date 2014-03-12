# generated automatically by aclocal 1.9.6 -*- Autoconf -*-

# Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
# 2005  Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

# ===========================================================================
#    http://www.gnu.org/software/autoconf-archive/ax_cflags_warn_all.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CFLAGS_WARN_ALL   [(shellvar [,default, [A/NA]])]
#   AX_CXXFLAGS_WARN_ALL [(shellvar [,default, [A/NA]])]
#   AX_FCFLAGS_WARN_ALL  [(shellvar [,default, [A/NA]])]
#
# DESCRIPTION
#
#   Try to find a compiler option that enables most reasonable warnings.
#
#   For the GNU compiler it will be -Wall (and -ansi -pedantic) The result
#   is added to the shellvar being CFLAGS, CXXFLAGS, or FCFLAGS by default.
#
#   Currently this macro knows about the GCC, Solaris, Digital Unix, AIX,
#   HP-UX, IRIX, NEC SX-5 (Super-UX 10), Cray J90 (Unicos 10.0.0.8), and
#   Intel compilers.  For a given compiler, the Fortran flags are much more
#   experimental than their C equivalents.
#
#    - $1 shell-variable-to-add-to : CFLAGS, CXXFLAGS, or FCFLAGS
#    - $2 add-value-if-not-found : nothing
#    - $3 action-if-found : add value to shellvariable
#    - $4 action-if-not-found : nothing
#
# LICENSE
#
#   Copyright (c) 2008 Guido U. Draheim <guidod@gmx.de>
#   Copyright (c) 2010 Rhys Ulerich <rhys.ulerich@gmail.com>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 3 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 10

AC_DEFUN([AX_CFLAGS_WARN_ALL],[dnl
AS_VAR_PUSHDEF([FLAGS],[CFLAGS])dnl
AS_VAR_PUSHDEF([VAR],[ac_cv_cflags_warn_all])dnl
AC_CACHE_CHECK([m4_ifval($1,$1,FLAGS) for maximum warnings],
VAR,[VAR="no, unknown"
 AC_LANG_PUSH([C])
 ac_save_[]FLAGS="$[]FLAGS"
for ac_arg dnl
in "-pedantic  % -Wall"       dnl   GCC
   "-xstrconst % -v"          dnl Solaris C
   "-std1      % -verbose -w0 -warnprotos" dnl Digital Unix
   "-qlanglvl=ansi % -qsrcmsg -qinfo=all:noppt:noppc:noobs:nocnd" dnl AIX
   "-ansi -ansiE % -fullwarn" dnl IRIX
   "+ESlit     % +w1"         dnl HP-UX C
   "-Xc        % -pvctl[,]fullmsg" dnl NEC SX-5 (Super-UX 10)
   "-h conform % -h msglevel 2" dnl Cray C (Unicos)
   #
do FLAGS="$ac_save_[]FLAGS "`echo $ac_arg | sed -e 's,%%.*,,' -e 's,%,,'`
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM],
                     [VAR=`echo $ac_arg | sed -e 's,.*% *,,'` ; break])
done
 FLAGS="$ac_save_[]FLAGS"
 AC_LANG_POP([C])
])
case ".$VAR" in
     .ok|.ok,*) m4_ifvaln($3,$3) ;;
   .|.no|.no,*) m4_ifvaln($4,$4,[m4_ifval($2,[
        AC_RUN_LOG([: m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $2"])
                      m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $2"])]) ;;
   *) m4_ifvaln($3,$3,[
   if echo " $[]m4_ifval($1,$1,FLAGS) " | grep " $VAR " 2>&1 >/dev/null
   then AC_RUN_LOG([: m4_ifval($1,$1,FLAGS) does contain $VAR])
   else AC_RUN_LOG([: m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $VAR"])
                      m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $VAR"
   fi ]) ;;
esac
AS_VAR_POPDEF([VAR])dnl
AS_VAR_POPDEF([FLAGS])dnl
])

dnl the only difference - the LANG selection... and the default FLAGS

AC_DEFUN([AX_CXXFLAGS_WARN_ALL],[dnl
AS_VAR_PUSHDEF([FLAGS],[CXXFLAGS])dnl
AS_VAR_PUSHDEF([VAR],[ax_cv_cxxflags_warn_all])dnl
AC_CACHE_CHECK([m4_ifval($1,$1,FLAGS) for maximum warnings],
VAR,[VAR="no, unknown"
 AC_LANG_PUSH([C++])
 ac_save_[]FLAGS="$[]FLAGS"
for ac_arg dnl
in "-pedantic  % -Wall"       dnl   GCC
   "-xstrconst % -v"          dnl Solaris C
   "-std1      % -verbose -w0 -warnprotos" dnl Digital Unix
   "-qlanglvl=ansi % -qsrcmsg -qinfo=all:noppt:noppc:noobs:nocnd" dnl AIX
   "-ansi -ansiE % -fullwarn" dnl IRIX
   "+ESlit     % +w1"         dnl HP-UX C
   "-Xc        % -pvctl[,]fullmsg" dnl NEC SX-5 (Super-UX 10)
   "-h conform % -h msglevel 2" dnl Cray C (Unicos)
   #
do FLAGS="$ac_save_[]FLAGS "`echo $ac_arg | sed -e 's,%%.*,,' -e 's,%,,'`
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM],
                     [VAR=`echo $ac_arg | sed -e 's,.*% *,,'` ; break])
done
 FLAGS="$ac_save_[]FLAGS"
 AC_LANG_POP([C++])
])
case ".$VAR" in
     .ok|.ok,*) m4_ifvaln($3,$3) ;;
   .|.no|.no,*) m4_ifvaln($4,$4,[m4_ifval($2,[
        AC_RUN_LOG([: m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $2"])
                      m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $2"])]) ;;
   *) m4_ifvaln($3,$3,[
   if echo " $[]m4_ifval($1,$1,FLAGS) " | grep " $VAR " 2>&1 >/dev/null
   then AC_RUN_LOG([: m4_ifval($1,$1,FLAGS) does contain $VAR])
   else AC_RUN_LOG([: m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $VAR"])
                      m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $VAR"
   fi ]) ;;
esac
AS_VAR_POPDEF([VAR])dnl
AS_VAR_POPDEF([FLAGS])dnl
])

dnl the only difference - the LANG selection... and the default FLAGS

AC_DEFUN([AX_FCFLAGS_WARN_ALL],[dnl
AS_VAR_PUSHDEF([FLAGS],[FCFLAGS])dnl
AS_VAR_PUSHDEF([VAR],[ax_cv_fcflags_warn_all])dnl
AC_CACHE_CHECK([m4_ifval($1,$1,FLAGS) for maximum warnings],
VAR,[VAR="no, unknown"
 AC_LANG_PUSH([Fortran])
 ac_save_[]FLAGS="$[]FLAGS"
for ac_arg dnl
in "-warn all  % -warn all"   dnl Intel
   "-pedantic  % -Wall"       dnl GCC
   "-xstrconst % -v"          dnl Solaris C
   "-std1      % -verbose -w0 -warnprotos" dnl Digital Unix
   "-qlanglvl=ansi % -qsrcmsg -qinfo=all:noppt:noppc:noobs:nocnd" dnl AIX
   "-ansi -ansiE % -fullwarn" dnl IRIX
   "+ESlit     % +w1"         dnl HP-UX C
   "-Xc        % -pvctl[,]fullmsg" dnl NEC SX-5 (Super-UX 10)
   "-h conform % -h msglevel 2" dnl Cray C (Unicos)
   #
do FLAGS="$ac_save_[]FLAGS "`echo $ac_arg | sed -e 's,%%.*,,' -e 's,%,,'`
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM],
                     [VAR=`echo $ac_arg | sed -e 's,.*% *,,'` ; break])
done
 FLAGS="$ac_save_[]FLAGS"
 AC_LANG_POP([Fortran])
])
case ".$VAR" in
     .ok|.ok,*) m4_ifvaln($3,$3) ;;
   .|.no|.no,*) m4_ifvaln($4,$4,[m4_ifval($2,[
        AC_RUN_LOG([: m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $2"])
                      m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $2"])]) ;;
   *) m4_ifvaln($3,$3,[
   if echo " $[]m4_ifval($1,$1,FLAGS) " | grep " $VAR " 2>&1 >/dev/null
   then AC_RUN_LOG([: m4_ifval($1,$1,FLAGS) does contain $VAR])
   else AC_RUN_LOG([: m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $VAR"])
                      m4_ifval($1,$1,FLAGS)="$m4_ifval($1,$1,FLAGS) $VAR"
   fi ]) ;;
esac
AS_VAR_POPDEF([VAR])dnl
AS_VAR_POPDEF([FLAGS])dnl
])

dnl  implementation tactics:
dnl   the for-argument contains a list of options. The first part of
dnl   these does only exist to detect the compiler - usually it is
dnl   a global option to enable -ansi or -extrawarnings. All other
dnl   compilers will fail about it. That was needed since a lot of
dnl   compilers will give false positives for some option-syntax
dnl   like -Woption or -Xoption as they think of it is a pass-through
dnl   to later compile stages or something. The "%" is used as a
dnl   delimiter. A non-option comment can be given after "%%" marks
dnl   which will be shown but not added to the respective C/CXXFLAGS.

dnl Autoconf macros for libmcrypt
dnl $id$

# This script detects libmcrypt version and defines
# LIBMCRYPT_CFLAGS, LIBMCRYPT_LIBS
# and LIBMCRYPT24 or LIBMCRYPT22 depending on libmcrypt version
# found.

# Modified for LIBMCRYPT -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBMCRYPT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libmcrypt, and define LIBMCRYPT_CFLAGS and LIBMCRYPT_LIBS
dnl
AC_DEFUN([AM_PATH_LIBMCRYPT],
[dnl
dnl Get the cflags and libraries from the libmcrypt-config script
dnl
AC_ARG_WITH(libmcrypt-prefix,
          AC_HELP_STRING([--with-libmcrypt-prefix=PFX], [prefix where libmcrypt is installed (optional)]),
          libmcrypt_config_prefix="$withval", libmcrypt_config_prefix="")

  if test x$libmcrypt_config_prefix != x ; then
     libmcrypt_config_args="$libmcrypt_config_args --prefix=$libmcrypt_config_prefix"
     if test x${LIBMCRYPT_CONFIG+set} != xset ; then
        LIBMCRYPT_CONFIG=$libmcrypt_config_prefix/bin/libmcrypt-config
     fi
  fi

  AC_PATH_PROG(LIBMCRYPT_CONFIG, libmcrypt-config, no)
  min_libmcrypt_version=ifelse([$1], ,2.4.0,$1)
  AC_MSG_CHECKING(for libmcrypt - version >= $min_libmcrypt_version)
  no_libmcrypt=""
  if test "$LIBMCRYPT_CONFIG" = "no" ; then
dnl libmcrypt-config was not found (pre 2.4.11 versions)
dnl Try to detect libmcrypt version
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

int
main ()
{
#if MCRYPT_API_VERSION <= 19991015 
/* version 2.2 */
    return 0;
#else
/* version 2.4 */
    return 1;
#endif /* 19991015 */
}
],  libmcrypt_config_version="2.2.0"
    if test x$libmcrypt_config_prefix != x ; then
	TTLIBS="-L${libmcrypt_config_prefix}/libs"
	TTINCLUDE="-I${libmcrypt_config_prefix}/include"
    fi
    LIBMCRYPT_CFLAGS="${TTINCLUDE}"
    LIBMCRYPT_LIBS="${TTLIBS} -lmcrypt"
    AC_DEFINE(LIBMCRYPT22, 1, [have libmcrypt 2.2])

,   libmcrypt_config_version="2.4.0"
    if test x$libmcrypt_config_prefix != x ; then
	TTLIBS="-L${libmcrypt_config_prefix}/libs"
	TTINCLUDE="-I${libmcrypt_config_prefix}/include"
    fi
    LIBMCRYPT_CFLAGS="${TTINCLUDE}"
    LIBMCRYPT_LIBS="${TTLIBS} -lmcrypt -lltdl ${LIBADD_DL}"
    AC_DEFINE(LIBMCRYPT24, 1, [have libmcrypt 2.4]))
  else
dnl libmcrypt-config was found
    LIBMCRYPT_CFLAGS=`$LIBMCRYPT_CONFIG $libmcrypt_config_args --cflags`
    LIBMCRYPT_LIBS=`$LIBMCRYPT_CONFIG $libmcrypt_config_args --libs`
    libmcrypt_config_version=`$LIBMCRYPT_CONFIG $libmcrypt_config_args --version`
    AC_DEFINE(LIBMCRYPT24, 1, [have libmcrypt 2.4])
  fi

  ac_save_CFLAGS="$CFLAGS"
  ac_save_LIBS="$LIBS"
  CFLAGS="$CFLAGS $LIBMCRYPT_CFLAGS"
  LIBS="$LIBS $LIBMCRYPT_LIBS"

dnl
dnl Now check if the installed libmcrypt is sufficiently new. Also sanity
dnl checks the results of libmcrypt-config to some extent
dnl
      rm -f conf.libmcrypttest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

#define TWO "2.2"

int
main ()
{
#if MCRYPT_API_VERSION <= 20010201

#if MCRYPT_API_VERSION <= 19991015 
/* version 2.2 */
    int x = mcrypt_get_key_size(MCRYPT_TWOFISH_128);
    system ("touch conf.libmcrypttest");

    if( strncmp( TWO, "$min_libmcrypt_version", strlen(TWO))) {
      printf("\n*** Requested libmcrypt %s, but LIBMCRYPT (%s)\n",
             "$min_libmcrypt_version", TWO );
      printf("*** was found!\n"); 
      return 1;
    }
    return 0;
#else
/* version 2.4 before 11 */
    MCRYPT td = mcrypt_module_open("twofish", NULL, "cbc", NULL);
    system ("touch conf.libmcrypttest");
    mcrypt_module_close(td);

    return 0;
#endif /* 19991015 */

#else

    system ("touch conf.libmcrypttest");

    if( strcmp( mcrypt_check_version(NULL), "$libmcrypt_config_version" ) )
    {
      printf("\n*** 'libmcrypt-config --version' returned %s, but LIBMCRYPT (%s)\n",
             "$libmcrypt_config_version", mcrypt_check_version(NULL) );
      printf("*** was found! If libmcrypt-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBMCRYPT. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libmcrypt-config was wrong, set the environment variable LIBMCRYPT_CONFIG\n");
      printf("*** to point to the correct copy of libmcrypt-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(mcrypt_check_version(NULL), LIBMCRYPT_VERSION ) )
    {
      printf("\n*** LIBMCRYPT header file (version %s) does not match\n", LIBMCRYPT_VERSION);
      printf("*** library (version %s)\n", mcrypt_check_version(NULL) );
    }
    else
    {
      if ( mcrypt_check_version( "$min_libmcrypt_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBMCRYPT (%s) was found.\n",
                mcrypt_check_version(NULL) );
        printf("*** You need a version of LIBMCRYPT newer than %s. The latest version of\n",
               "$min_libmcrypt_version" );
        printf("*** LIBMCRYPT is always available from ftp://mcrypt.hellug.gr/pub/mcrypt.\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libmcrypt-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBMCRYPT, but you can also set the LIBMCRYPT_CONFIG environment to point to the\n");
        printf("*** correct copy of libmcrypt-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time)\n");
      }
    }
  return 1;

#endif /* 20010201 */

}
],, no_libmcrypt=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"


  if test "x$no_libmcrypt" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libmcrypttest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     
     if test -f conf.libmcrypttest ; then
        :
     else
          echo "*** Could not run libmcrypt test program, checking why..."
          CFLAGS="$CFLAGS $LIBMCRYPT_CFLAGS"
          LIBS="$LIBS $LIBMCRYPT_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
],      [ 
#if MCRYPT_API_VERSION <= 20010201

#if MCRYPT_API_VERSION <= 19991015 
/* version 2.2 */
    int x = mcrypt_get_key_size(MCRYPT_TWOFISH_128);
    return 0;
#else
/* version 2.4 before 11 */
    MCRYPT td = mcrypt_module_open("twofish", NULL, "cbc", NULL);
    mcrypt_module_close(td);
    return 0;
#endif /* 19991015 */
#else

return !!mcrypt_check_version(NULL); 

#endif /* 20010201 */

],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBMCRYPT or finding the wrong"
          echo "*** version of LIBMCRYPT. If it is not finding LIBMCRYPT, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBMCRYPT was incorrectly installed"
          echo "*** or that you have moved LIBMCRYPT since it was installed. In the latter case, you"
          echo "*** may want to edit the libmcrypt-config script: $LIBMCRYPT_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
     fi
     
     LIBMCRYPT_CFLAGS=""
     LIBMCRYPT_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.libmcrypttest
  AC_SUBST(LIBMCRYPT_CFLAGS)
  AC_SUBST(LIBMCRYPT_LIBS)
])

dnl *-*wedit:notab*-*  Please keep this as the last line.

