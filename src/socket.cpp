/*
 * javalike cross-platform socket abstraction
 * Copyright (C) 2009-2011 BebboSoft, updated 2024-2025 by Stefan Franke <stefan@franke.ms>
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
 * Project: javalike
 * Module: socket.cpp
 *
 * Purpose:
 *  - Provide a unified socket API across Windows, Linux, and AmigaOS
 *  - Wrap platform-specific differences (WSAStartup, closesocket, bind quirks)
 *  - Implement SocketBase, Socket, ServerSocket, and stream classes
 *
 * Notes:
 *  - Windows: initializes Winsock via WSAStartup
 *  - Linux: uses standard BSD sockets with errno for error reporting
 *  - AmigaOS: integrates with bsdsocket.library and requires explicit bind before connect
 *  - Provides InputStream/OutputStream wrappers for socket I/O
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifdef __WIN32__

#define SHUT_RDWR 2
typedef int socklen_t;

static struct _ {
	_() {
		WSADATA wsaData;
		WSAStartup(((WORD) 3 << 8) | (WORD) 1, &wsaData);
	}
} _;

#define GETERROR WSAGetLastError()

#endif

#if defined(__linux__)
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h>

#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define GETERROR errno
#define closesocket close
#elif  defined(__AMIGA__)
#include <amistdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>
#include <netinet/tcp.h>

inline int closesocket(int s) {
	return close(s);
}

#endif

#include "io/socket.h"

#undef DEBUG

using namespace io;
using namespace net;

SocketBase::SocketBase() :
sd(INVALID_SOCKET), addr(), timeout() {
	setTimeout(0x7ffffff, 0);
}

SocketBase::~SocketBase() {
	if (sd != INVALID_SOCKET)
		disconnect();
}

#define IDN_USE_STD3_ASCII_RULES    0x02
// extern "C" int __stdcall IdnToAscii(unsigned long dwFlags, char const * lpUnicodeCharStr, int cchUnicodeChar, char const * lpASCIICharStr, int cchASCIIChar);

int SocketBase::initSockAddr(sockaddr_in &addr, unsigned short ipPort, char const * const ipAddr_) {
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (ipAddr_) {
#ifdef UNICODE
		char ipAddr[256];
		for (int i = 0; i < 255; ++i) {
			char c = ipAddr[i] = (char) ipAddr_[i];
			if (!c)
				break;
		}
		ipAddr[255] = 0;
		// IdnToAscii(IDN_USE_STD3_ASCII_RULES, ipAddr_, wcslen(ipAddr_), ipAddr, sizeof(ipAddr));
#else
    char const *  ipAddr = ipAddr_;
#endif

		hostent * host = gethostbyname(ipAddr);
		if (!host)
			return false;

		if (!host->h_addr_list)
			addr.sin_addr.s_addr = inet_addr((char *)host->h_name);
		else
			addr.sin_addr.s_addr = *(u_long*) *host->h_addr_list;
	} else {
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	addr.sin_port = htons(ipPort);
	return true;
}

int SocketBase::disconnect() {
	if (sd == INVALID_SOCKET || ::shutdown(sd, SHUT_RDWR) == SOCKET_ERROR || ::closesocket(sd) == SOCKET_ERROR)
		return INVALID_SOCKET;
	return 0;
}

int SocketBase::setTcpNoDelay(int onOff) {
	return ::setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char *) &onOff, 1);
}

int SocketBase::setKeepAlive(int onOff) {
	return ::setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (char *) &onOff, 1);
}

Socket::Socket(SOCKET sock) : SocketBase(), is(0), os(0) {
	sd = sock;
}

Socket::Socket(char const * const ipAddr, unsigned short ipPort) :
SocketBase(), is(0), os(0) {
#ifdef __WIN32__  
	WSADATA wsaData;
	WSAStartup(((WORD) 3 << 8) | (WORD) 1, &wsaData);
#endif
	if (initSockAddr(addr, ipPort, ipAddr)) {
		connect();
		setTcpNoDelay(true);
	}
}

Socket::Socket(SOCKET s, sockaddr_in const & addr_) :
SocketBase(), is(0), os(0) {
	sd = s;
	addr = addr_;
	setTcpNoDelay(true);
}

Socket::~Socket() {
	delete is;
	delete os;
}

int Socket::connect() {
	if ((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    return GETERROR;

#ifdef __AMIGA__
	// bind to a local port before connecting
	struct sockaddr_in sinLocal;
	memset(&sinLocal, 0, sizeof(sinLocal));

	sinLocal.sin_family = AF_INET;
	sinLocal.sin_addr.s_addr = INADDR_ANY;
	if (::bind(sd, (struct sockaddr *)&sinLocal, sizeof(sinLocal)))
	    return GETERROR;
#endif
	if (::connect(sd, (struct sockaddr *) &addr, sizeof(addr)) == SOCKET_ERROR)
    return GETERROR;
	return 0;
}

int Socket::send(void const * const buffer, unsigned int size) {
//	fd_set writeFds;
//	FD_ZERO(&writeFds);
//	FD_SET(sd, &writeFds);
//	if (::select(sd + 1, NULL, &writeFds, NULL, &timeout) <= 0)
//		return -1;
	int sent = ::send(sd, (char const *) buffer, size, 0);
	if (!sent)
		return -1;
	return size;
}

int Socket::receive(void *buffer, unsigned int size) {
//	fd_set readFds;
//	FD_ZERO(&readFds);
//	FD_SET(sd, &readFds);
//	if (select(sd + 1, &readFds, NULL, NULL, &timeout) <= 0)
//		return -1;
	unsigned int read = recv(sd, (char *) buffer, size, 0);
	return read;
}

int Socket::canRead() {
	timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = 0;
	fd_set readFds;
	FD_ZERO(&readFds);
	FD_SET(sd, &readFds);
	return select(sd + 1, &readFds, NULL, NULL, &tv) > 0;
}

InputStream * Socket::getInputStream() {
	if (!is)
		is = new SocketInputStream(this);
	return is;
}

OutputStream * Socket::getOutputStream() {
	if (!os)
		os = new SocketOutputStream(this);
	return os;
}

int SocketInputStream::available() {
	return socket->canRead() ? 1 : 0;
}
int SocketInputStream::read() {
	char b[1];
	int len = socket->receive(b, 1);
#ifdef DEBUG
	printf("read() -> %ld\n", len);
#endif
	if (len)
		return 0xff & b[0];
	return -1;
}
int SocketInputStream::read(void * buffer, int len) {
	int r = socket->receive(buffer, len);
#ifdef DEBUG
	printf("read(%08lx, %ld) -> %ld\n", buffer, len, r);
#endif
	return r;
}
int SocketInputStream::close() {
	return socket->disconnect();
}

int SocketOutputStream::write(int byte) {
	char b[1] = { (char) byte };
	return socket->send(b, 1);
}
int SocketOutputStream::write(void const * buffer, int len) {
	return socket->send(buffer, len);
}
int SocketOutputStream::close() {
	return socket->disconnect();
}

ServerSocket::ServerSocket(unsigned short ipPort, char const * const bindAddr, int maxConn) :
SocketBase(), backLog(maxConn) {
	initSockAddr(addr, ipPort, bindAddr);
	listen();
}

int ServerSocket::listen() {
	if ((sd = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return INVALID_SOCKET;
	if (::bind(sd, (struct sockaddr *) &addr, sizeof(addr)) == SOCKET_ERROR) {
		disconnect();
		return INVALID_SOCKET;
	}
	return ::listen(sd, backLog);
}

Socket * ServerSocket::accept() {
	struct sockaddr_in addr;
    socklen_t sz = sizeof(addr);
	SOCKET s = ::accept(sd, (struct sockaddr *) &addr, &sz);
	if (!s)
		return 0;
	Socket * socket = new Socket(s, addr);
	socket->setTimeout(timeout.tv_sec, timeout.tv_usec);
	return socket;
}

//#define CLIENT
//#define SERVER

#if defined(CLIENT) || defined(SERVER)
#include <stdio.h>
#endif

#ifdef CLIENT
int main() {
	//  Socket socket(BCHAR("85.214.17.7"), 80);
	Socket socket(BCHAR("bejy.net"), 80);
	socket.setTimeout(30, 0);
	char * msg = "GET / HTTP1.0\r\nHost: www.bejy.net\r\n\r\n";
	socket.send(msg, strlen(msg));
	char buffer[1025];
	for (;;) {
		int read = socket.receive(buffer, 1024);
		if (read < 0) {
      read = GETERROR;
			break;
		}
		if (read == 0)
			continue;
		buffer[read] = 0;
		puts(buffer);
	}
	return 0;
}
#endif

#ifdef SERVER
int main() {
	ServerSocket server(80);
	server.setTimeout(60, 0);
	char buffer[1025];
	for (int i = 0; i < 3; ++i) {
		Socket *s = server.accept();
		if (!s)
			continue;
		for (;;) {
			int read = s->receive(buffer, 1024);
			if (read < 0) {
				break;
			}
			buffer[read] = 0;
			puts( buffer);
		}

		delete s;
	}
	return 0;
}
#endif
