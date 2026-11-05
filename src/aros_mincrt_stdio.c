/*
 * aros_mincrt_stdio - bebboget additions to the x86_64 minimal C runtime
 * Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version (GPLv3+).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ----------------------------------------------------------------------
 *
 * aros_mincrt.c is shared with bebbossh-aros and stays unchanged; this file
 * adds what bebboget needs on top of it:
 *  - the C++ static constructors: __noinitexitsets keeps the autoinit code
 *    (which calls libraries without r12) from running them, so they run here
 *  - the posixc stdio entry points the crosstools headers map stdio to;
 *    stdout and stderr both go to Output(), stdin is Input()
 *  - gmtime(), ctime(), mktime() (UTC) and an sscanf() for "%Nd" fields
 * The printf family reads %ld as 32 bit, as the Amiga code passes int.
 */
#if defined(__AROS__) && defined(BEBBOSSH_AROS_MINCRT)

#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <exec/types.h>
#include <exec/execbase.h>
#include <aros/symbolsets.h>
#include <dos/dos.h>

#include "aros_mincrt_wrappers.h"

int bebbossh_aros_log_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);
int snprintf(char *buf, size_t size, const char *fmt, ...);

/* C++ static constructors: ctors last to first, then init_array first to last */
/* collect-aros builds both lists from the .ctors and .init_array sections, but
   only if the link has such a section: these empty entries make sure it has */
DECLARESET(CTORS)
DECLARESET(INIT_ARRAY)

static void bebboget_aros_no_ctor(void)
{
}

static void (*const bebboget_aros_ctors_anchor)(void)
	__attribute__((section(".ctors"), used)) = bebboget_aros_no_ctor;
static void (*const bebboget_aros_init_array_anchor)(void)
	__attribute__((section(".init_array"), used)) = bebboget_aros_no_ctor;
void ___startup_entries_next(struct ExecBase *SysBase);

static void bebboget_aros_run_ctors(struct ExecBase *sysBase)
{
	long pos;
	void (*fn)(void);

	ForeachElementInSet(SETNAME(CTORS), -1, pos, fn)
		if (fn)
			fn();
	ForeachElementInSet(SETNAME(INIT_ARRAY), 1, pos, fn)
		fn();
	___startup_entries_next(sysBase);
}

ADD2SET(bebboget_aros_run_ctors, PROGRAM_ENTRIES, -124)

/* stdio: the FILE pointers are only tokens */
static char stdinToken, stdoutToken, stderrToken;

void *__posixc_getstdin(void)
{
	return &stdinToken;
}

void *__posixc_getstdout(void)
{
	return &stdoutToken;
}

void *__posixc_getstderr(void)
{
	return &stderrToken;
}

static int writeOut(const char *s, size_t len)
{
	return bebbossh_aros_write(bebbossh_aros_output(), s, (LONG)len) == (LONG)len ? (int)len : -1;
}

int __posixc_vfprintf(void *stream, const char *fmt, va_list ap)
{
	char buf[1024];
	int len;

	(void)stream;
	len = bebbossh_aros_log_vsnprintf(buf, sizeof(buf), fmt, ap);
	writeOut(buf, strlen(buf));
	return len;
}

int __posixc_fprintf(void *stream, const char *fmt, ...)
{
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = __posixc_vfprintf(stream, fmt, ap);
	va_end(ap);
	return len;
}

int __posixc_printf(const char *fmt, ...)
{
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = __posixc_vfprintf(&stdoutToken, fmt, ap);
	va_end(ap);
	return len;
}

int __posixc_fputs(const char *s, void *stream)
{
	(void)stream;
	return writeOut(s, strlen(s)) < 0 ? -1 : 0;
}

int __posixc_puts(const char *s)
{
	if (writeOut(s, strlen(s)) < 0 || writeOut("\n", 1) < 0)
		return -1;
	return 0;
}

int __posixc_putchar(int c)
{
	char ch = (char)c;
	return writeOut(&ch, 1) < 0 ? -1 : (unsigned char)ch;
}

int __posixc_fflush(void *stream)
{
	/* stdin: drop what is buffered, e.g. the argument line that RunCommand()
	   puts into the Input() buffer, so the first fgets() waits for the user */
	if (stream == &stdinToken)
		bebbossh_aros_flush(bebbossh_aros_input());
	return 0;
}

char *__posixc_fgets(char *buf, int len, void *stream)
{
	(void)stream;
	return bebbossh_aros_fgets(bebbossh_aros_input(), buf, len);
}

/* files: read only, which is all installcerts needs */
void *malloc(size_t size);
void free(void *ptr);

struct MiniFile {
	BPTR fh;
};

void *__posixc_fopen(const char *name, const char *mode)
{
	struct MiniFile *f;
	BPTR fh;

	if (!mode || mode[0] != 'r' || strchr(mode, '+'))
		return 0;
	fh = bebbossh_aros_open(name, MODE_OLDFILE);
	if (!fh)
		return 0;
	f = (struct MiniFile *)malloc(sizeof(*f));
	if (!f) {
		bebbossh_aros_close(fh);
		return 0;
	}
	f->fh = fh;
	return f;
}

int __posixc_fclose(void *stream)
{
	struct MiniFile *f = (struct MiniFile *)stream;

	if (!f)
		return -1;
	bebbossh_aros_close(f->fh);
	free(f);
	return 0;
}

size_t __posixc_fread(void *buf, size_t size, size_t count, void *stream)
{
	struct MiniFile *f = (struct MiniFile *)stream;
	LONG got;

	if (!f || !size || !count)
		return 0;
	got = bebbossh_aros_read(f->fh, buf, (LONG)(size * count));
	return got > 0 ? (size_t)got / size : 0;
}

int __posixc_fseek(void *stream, long offset, int whence)
{
	struct MiniFile *f = (struct MiniFile *)stream;
	LONG mode = whence == 2 ? OFFSET_END : whence == 1 ? OFFSET_CURRENT : OFFSET_BEGINNING;

	if (!f)
		return -1;
	return bebbossh_aros_seek(f->fh, (LONG)offset, mode) < 0 ? -1 : 0;
}

long __posixc_ftell(void *stream)
{
	struct MiniFile *f = (struct MiniFile *)stream;

	if (!f)
		return -1;
	return (long)bebbossh_aros_seek(f->fh, 0, OFFSET_CURRENT);
}

/* time: days from 1970-01-01 for a proleptic Gregorian date and back */
static long daysFromCivil(long y, unsigned m, unsigned d)
{
	long era;
	unsigned yoe, doy, doe;

	y -= m <= 2;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = (unsigned)(y - era * 400);
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + (long)doe - 719468;
}

time_t mktime(struct tm *tm)
{
	long y = tm->tm_year + 1900L + tm->tm_mon / 12;
	int m = tm->tm_mon % 12;

	if (m < 0) {
		m += 12;
		--y;
	}
	return (time_t)(((daysFromCivil(y, (unsigned)m + 1, 1) + tm->tm_mday - 1) * 24 + tm->tm_hour) * 60
			+ tm->tm_min) * 60 + tm->tm_sec;
}

struct tm *gmtime(const time_t *clock)
{
	static struct tm r;
	long t = (long)*clock;
	long days = t / 86400, secs = t % 86400;
	long z, era;
	unsigned doe, yoe, doy, mp;

	if (secs < 0) {
		secs += 86400;
		--days;
	}
	memset(&r, 0, sizeof(r));
	r.tm_hour = (int)(secs / 3600);
	r.tm_min = (int)(secs / 60 % 60);
	r.tm_sec = (int)(secs % 60);
	r.tm_wday = (int)((days % 7 + 11) % 7); /* 1970-01-01 was a Thursday */
	z = days + 719468;
	era = (z >= 0 ? z : z - 146096) / 146097;
	doe = (unsigned)(z - era * 146097);
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	mp = (5 * doy + 2) / 153;
	r.tm_mday = (int)(doy - (153 * mp + 2) / 5 + 1);
	r.tm_mon = (int)(mp < 10 ? mp + 2 : mp - 10);
	r.tm_year = (int)(yoe + era * 400 + (r.tm_mon < 2) - 1900);
	r.tm_yday = (int)(days - daysFromCivil(r.tm_year + 1900L, 1, 1));
	return &r;
}

char *ctime(const time_t *clock)
{
	static const char wday[] = "SunMonTueWedThuFriSat";
	static const char mon[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
	static char buf[32];
	char w[4], m[4];
	struct tm *t = gmtime(clock);

	memcpy(w, wday + 3 * t->tm_wday, 3);
	w[3] = 0;
	memcpy(m, mon + 3 * t->tm_mon, 3);
	m[3] = 0;
	snprintf(buf, sizeof(buf), "%s %s %2d %02d:%02d:%02d %d\n", w, m,
			t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, t->tm_year + 1900);
	return buf;
}

/* sscanf: literals, white space and %d / %Nd only, which is what bebboget uses */
int sscanf(const char *s, const char *fmt, ...)
{
	va_list ap;
	int n = 0;

	va_start(ap, fmt);
	while (*fmt) {
		if (*fmt == '%' && fmt[1] != '%') {
			int width = 0, neg = 0, got = 0, v = 0;
			++fmt;
			while (*fmt >= '0' && *fmt <= '9')
				width = width * 10 + *fmt++ - '0';
			if (*fmt++ != 'd')
				break;
			while (*s == ' ' || *s == '\t')
				++s;
			if (*s == '-' || *s == '+') {
				neg = *s++ == '-';
				if (width)
					--width;
			}
			while (*s >= '0' && *s <= '9' && (!width || got < width)) {
				v = v * 10 + *s++ - '0';
				++got;
			}
			if (!got)
				break;
			*va_arg(ap, int *) = neg ? -v : v;
			++n;
		} else if (*fmt == ' ') {
			while (*s == ' ' || *s == '\t')
				++s;
			++fmt;
		} else {
			if (*fmt == '%')
				++fmt;
			if (*s != *fmt)
				break;
			++s;
			++fmt;
		}
	}
	va_end(ap);
	return n;
}

#endif
