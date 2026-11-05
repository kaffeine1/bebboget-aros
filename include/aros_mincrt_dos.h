/*
 * aros_mincrt_dos.h - the dos/exec r12 wrappers of aros_mincrt_wrappers.h
 * without its socket macros, which clash with the C++ socket classes; the
 * socket calls are functions of socket_glue_aros.c.
 */
#ifndef BEBBOGET_AROS_MINCRT_DOS_H
#define BEBBOGET_AROS_MINCRT_DOS_H

#include "aros_mincrt_wrappers.h"

#undef socket
#undef bind
#undef setsockopt
#undef listen
#undef accept
#undef getsockname
#undef connect
#undef send
#undef recv
#undef shutdown
#undef inet_addr
#undef gethostbyname

#endif
