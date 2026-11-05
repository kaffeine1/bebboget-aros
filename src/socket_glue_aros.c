/*
 * bebboget AROS BSD socket glue layer
 * Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
 * Based on the Amiga socket glue of bebboget by Stefan Franke.
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
 * Project: bebboget
 * Module: AROS BSD socket glue
 *
 * Purpose:
 *  - On AROS the socket calls exist only as macros of proto/bsdsocket.h,
 *    which cannot be used as ::connect() etc. in C++. This file turns them
 *    into real functions; socket.cpp sees only the prototypes
 *    (BSDSOCKET_NOLIBDEFINES).
 *  - bsdsocket.library is opened and closed by the AROS startup (ADD2LIBS).
 *  - x86_64 (mincrt): the init sets do not run, so the library is opened at
 *    the first call, and every call goes through the r12 wrappers of
 *    aros_mincrt.c.
 * ----------------------------------------------------------------------
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#if defined(BEBBOSSH_AROS_MINCRT)
#include <stdio.h>
#include <stdlib.h>
#include "aros_mincrt_wrappers.h"

struct Library *SocketBase;

static void closeSocketBase(void) {
	bebbossh_aros_close_library(SocketBase);
	SocketBase = 0;
}

static int openSocketBase(void) {
	static int failed;
	if (!SocketBase && !failed) {
		SocketBase = bebbossh_aros_open_library("bsdsocket.library", 3);
		if (SocketBase)
			atexit(closeSocketBase);
		else {
			failed = 1;
			puts("can't open bsdsocket.library");
		}
	}
	return SocketBase != 0;
}

int (socket)(int domain, int type, int protocol) {
	return openSocketBase() ? bebbossh_aros_socket(SocketBase, domain, type, protocol) : -1;
}

int (bind)(int s, const struct sockaddr *name, socklen_t namelen) {
	return openSocketBase() ? bebbossh_aros_bind(SocketBase, s, (struct sockaddr *)name, namelen) : -1;
}

int (listen)(int s, int backlog) {
	return openSocketBase() ? bebbossh_aros_listen(SocketBase, s, backlog) : -1;
}

int (accept)(int s, struct sockaddr *addr, socklen_t *addrlen) {
	return openSocketBase() ? bebbossh_aros_accept(SocketBase, s, addr, addrlen) : -1;
}

int (connect)(int s, const struct sockaddr *name, socklen_t namelen) {
	return openSocketBase() ? bebbossh_aros_connect(SocketBase, s, (struct sockaddr *)name, namelen) : -1;
}

int (send)(int s, const void *msg, int len, int flags) {
	return openSocketBase() ? bebbossh_aros_send(SocketBase, s, msg, len, flags) : -1;
}

int (recv)(int s, void *buf, int len, int flags) {
	return openSocketBase() ? bebbossh_aros_recv(SocketBase, s, buf, len, flags) : -1;
}

int (shutdown)(int s, int how) {
	return openSocketBase() ? bebbossh_aros_shutdown(SocketBase, s, how) : -1;
}

int (setsockopt)(int s, int level, int optname, const void *optval, socklen_t optlen) {
	return openSocketBase() ? bebbossh_aros_setsockopt(SocketBase, s, level, optname, optval, optlen) : -1;
}

struct hostent *(gethostbyname)(const char *name) {
	return openSocketBase() ? bebbossh_aros_gethostbyname(SocketBase, name) : 0;
}

unsigned long (inet_addr)(const char *cp) {
	return openSocketBase() ? bebbossh_aros_inet_addr(SocketBase, cp) : 0xffffffffUL;
}

int (CloseSocket)(int s) {
	return openSocketBase() ? bebbossh_aros_close_socket(SocketBase, s) : -1;
}

int (WaitSelect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		struct timeval *timeout, ULONG *sigmask) {
	return openSocketBase()
			? bebbossh_aros_wait_select(SocketBase, nfds, readfds, writefds, exceptfds, timeout, sigmask) : -1;
}

#else
#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <aros/symbolsets.h>

ADD2LIBS("bsdsocket.library", 3, struct Library *, SocketBase);

/* the AROS One i386 SDK declares these pointers without const, newer SDKs with */
#if defined(__i386__)
#define GLUE_CONST
#else
#define GLUE_CONST const
#endif

/* (name) keeps the function-like macro from expanding in the definition */

int (socket)(int domain, int type, int protocol) {
	return socket(domain, type, protocol);
}

int (bind)(int s, GLUE_CONST struct sockaddr *name, socklen_t namelen) {
	return bind(s, name, namelen);
}

int (listen)(int s, int backlog) {
	return listen(s, backlog);
}

int (accept)(int s, struct sockaddr *addr, socklen_t *addrlen) {
	return accept(s, addr, addrlen);
}

int (connect)(int s, GLUE_CONST struct sockaddr *name, socklen_t namelen) {
	return connect(s, name, namelen);
}

int (send)(int s, const void *msg, int len, int flags) {
	return send(s, msg, len, flags);
}

int (recv)(int s, void *buf, int len, int flags) {
	return recv(s, buf, len, flags);
}

int (shutdown)(int s, int how) {
	return shutdown(s, how);
}

int (setsockopt)(int s, int level, int optname, GLUE_CONST void *optval, socklen_t optlen) {
	return setsockopt(s, level, optname, optval, optlen);
}

struct hostent *(gethostbyname)(const char *name) {
	return gethostbyname(name);
}

unsigned long (inet_addr)(const char *cp) {
	return inet_addr(cp);
}

int (CloseSocket)(int s) {
	return CloseSocket(s);
}

int (WaitSelect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		struct timeval *timeout, ULONG *sigmask) {
	return WaitSelect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

#endif
