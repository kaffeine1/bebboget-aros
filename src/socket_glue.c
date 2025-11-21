/*
 * bebboget Amiga BSD socket glue layer
 * Copyright (C) 2024-2025  Stefan Franke <stefan@franke.ms>
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
 * Module: Amiga BSD socket glue
 *
 * Purpose:
 *  - Provide thin wrappers around bsdsocket.library functions
 *  - Ensure proper initialization and cleanup of SocketBase
 *  - Export C-style functions with global symbols for linkage
 *
 * Notes:
 *  - Functions are wrapped with __stdargs and exported via inline assembly labels
 *  - Initialization hooks (ADD2INIT/ADD2EXIT) open and close bsdsocket.library
 *  - This glue layer allows portable socket code to run on AmigaOS
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <proto/bsdsocket.h>
#include <proto/exec.h>
#include <stabs.h>

#define __NO_NET_API
#include <netdb.h>
#include <amistdio.h>

struct Library * SocketBase;

void __socket_glue_init() {
	SocketBase = OldOpenLibrary("bsdsocket.library");
}

void __socket_glue_exit() {
	CloseLibrary(SocketBase);
}

ADD2INIT(__socket_glue_init, -40);
ADD2EXIT(__socket_glue_exit, -40);

__asm("_listen: .globl _listen");
__stdargs
int xlisten(int socket, int n) {
	return listen(socket, n);
}

__asm("_inet_addr: .globl _inet_addr");
__stdargs
in_addr_t xinet_addr(const char * name) {
	return inet_addr((char *)name);
}

__asm("_shutdown: .globl _shutdown");
__stdargs
int xshutdown(int socket, int how)   {
	return shutdown(socket, how);
}

__asm("_connect: .globl _connect");
__stdargs
int xconnect(int socket, struct sockaddr * addr, socklen_t len) {
	return connect(socket, addr, len);
}

__asm("_accept: .globl _accept");
__stdargs
int xaccept(int socket, struct sockaddr * addr, socklen_t * lenp) {
	return accept(socket, addr, lenp);
}

__asm("_bind: .globl _bind");
__stdargs
int xbind(int socket, struct sockaddr * addr, socklen_t len) {
	return bind(socket, addr, len);
}

__asm("_select: .globl _select");
__stdargs
int xselect(int __n, fd_set *__readfds, fd_set *__writefds,
		 fd_set *__exceptfds, struct timeval *__timeout) {
	return WaitSelect(__n, __readfds, __writefds, __exceptfds, __timeout, 0);
}

__asm("_recv: .globl _recv");
__stdargs
int xrecv(int socket, void * buffer, int size, int flags) {
	return recv(socket, buffer, size, flags);
}

__asm("_send: .globl _send");
__stdargs
int xsend(int socket, void * buffer, int size, int flags) {
	return send(socket, buffer, size, flags);
}

__asm("_socket: .globl _socket");
__stdargs
int xsocket(int ns, int style, int proto) {
	return socket(ns, style, proto);
}

__asm("_gethostbyname: .globl _gethostbyname");
__stdargs
struct hostent * xgethostbyname(char const * name)  {
	return gethostbyname((char *)name);
}

__asm("_setsockopt: .globl _setsockopt");
__stdargs
int xsetsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len) {
	return setsockopt(socket, level, option_name, (char *)option_value, option_len);
}

__stdargs
int ioctlsocket(int socket, int req, unsigned long * argp) {
	return IoctlSocket(socket, req, argp);
}
