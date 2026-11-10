/*
 * What the AROS aarch64 build needs from posixc.library, which it does not
 * link: every program that opens posixc.library loses about 160 KB when it
 * ends, because the library opens stdc.library and stdcio.library for
 * itself and does not close them.
 */
#include <proto/dos.h>
#include <dos/dos.h>
#include <sys/time.h>

/* AmigaDOS counts from 1978, time_t from 1970: 2922 days. */
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	struct DateStamp ds;

	(void)tz;
	if (!tv)
		return -1;

	DateStamp(&ds);
	tv->tv_sec = (ds.ds_Days + 2922) * 86400 + ds.ds_Minute * 60
			+ ds.ds_Tick / TICKS_PER_SECOND;
	tv->tv_usec = (ds.ds_Tick % TICKS_PER_SECOND) * (1000000 / TICKS_PER_SECOND);
	return 0;
}
