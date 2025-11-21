/*
 * javalike Socket interface
 * Copyright (C) 2009-2011, 2024-2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide TCP client and server socket classes with stream
 *          integration for Amiga and Windows platforms.
 *
 * Features:
 *  - SocketBase: common functionality for client and server sockets
 *  - Socket: TCP client connectivity with InputStream/OutputStream
 *  - ServerSocket: TCP server connectivity with accept()
 *  - SocketInputStream / SocketOutputStream: stream wrappers for sockets
 *
 * Notes:
 *  - DONOTCOPY macro prevents copying of socket classes
 *  - Supports Amiga and Windows socket APIs
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef DONOTCOPY
#define DONOTCOPY(T) T & operator=(T const&); T(T const&)
#endif

#ifndef __IO_SOCKET_H__
#define __IO_SOCKET_H__

#ifndef __IO_STREAM_H__
#include <io/stream.h>
#endif

#ifdef __WIN32__
#include <windows.h>
#include <winsock.h>
#else
#include <netinet/in.h>
typedef int SOCKET;
#if defined(__AMIGA__)

#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define GETERROR       (-1)
#endif
#endif

using namespace io;

namespace net {

    /**
     * @class SocketBase
     * @brief Base class for Socket and ServerSocket.
     *
     * Provides common socket functionality such as binding,
     * address initialization, disconnect, and socket options.
     */
    class SocketBase {
		// Prevent copying
		SocketBase(SocketBase const&) = delete;
		SocketBase& operator=(SocketBase const&) = delete;
    protected:
        SOCKET sd;                ///< Socket descriptor
        struct sockaddr_in addr;  ///< Socket address
        struct timeval timeout;   ///< Timeout configuration

        int bind();
        static int initSockAddr(sockaddr_in& addr, unsigned short ipPort, char const* const ipAddr = NULL);

        SocketBase();
        virtual ~SocketBase();

    public:
        inline sockaddr_in const& getAddress() const { return addr; }
        inline void setTimeout(int seconds, int microSeconds) {
            timeout.tv_sec = seconds;
            timeout.tv_usec = microSeconds;
        }
        int disconnect();
        int setTcpNoDelay(int onOff);
        int setKeepAlive(int onOff);
    };

    /**
     * @class Socket
     * @brief Provides TCP client connectivity.
     */
    class Socket : public SocketBase {
		// Prevent copying
		Socket(Socket const&) = delete;
		Socket& operator=(Socket const&) = delete;
		friend class ServerSocket;

        InputStream* is;
        OutputStream* os;

        int connect();
        Socket(SOCKET socket, sockaddr_in const& addr);

    public:
        Socket(SOCKET sock);
        Socket(char const* const ipAddr, unsigned short ipPort);
        ~Socket();

        int cancelBlockingCall();
        int send(void const* const buffer, unsigned int size);
        int receive(void* buffer, unsigned int size);
        int canRead();

        InputStream* getInputStream();
        OutputStream* getOutputStream();
    };

    /**
     * @class ServerSocket
     * @brief Provides TCP server connectivity.
     */
    class ServerSocket : public SocketBase {
        DONOTCOPY(ServerSocket);

        int backLog;
        int listen();

    public:
        ServerSocket(unsigned short ipPort, char const* const bindAddr = "0.0.0.0", int backLog = SOMAXCONN);
        Socket* accept();
    };

    /**
     * @class SocketInputStream
     * @brief Input stream wrapper for Socket.
     */
    class SocketInputStream : public InputStream {
        DONOTCOPY(SocketInputStream);
        friend class Socket;
        Socket* socket;
        inline SocketInputStream(Socket* s) : InputStream(), socket(s) {}
        virtual int available();
        virtual int read();
        virtual int read(void* buffer, int len);
        virtual int close();
    };

    /**
     * @class SocketOutputStream
     * @brief Output stream wrapper for Socket.
     */
    class SocketOutputStream : public OutputStream {
        DONOTCOPY(SocketOutputStream);
        friend class Socket;
        Socket* socket;
        SocketOutputStream(Socket* s) : OutputStream(), socket(s) {}
        virtual int write(int byte);
        virtual int write(void const* buffer, int len);
        virtual int close();
    };

}; // namespace net

#endif /* __IO_SOCKET_H__ */
