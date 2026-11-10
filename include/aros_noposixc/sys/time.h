/*
 * <sys/time.h> for the AROS aarch64 build without posixc.library:
 * struct timeval and gettimeofday(), which is in src/aros_noposixc.c.
 */
#ifndef BEBBOGET_NOPOSIXC_SYS_TIME_H
#define BEBBOGET_NOPOSIXC_SYS_TIME_H

#include <aros/types/timeval_s.h>

struct timezone;

#ifdef __cplusplus
extern "C" {
#endif

int gettimeofday(struct timeval *tv, struct timezone *tz);

#ifdef __cplusplus
}
#endif

#endif
