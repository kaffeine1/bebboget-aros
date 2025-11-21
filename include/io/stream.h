/*
 * javalike Stream interface
 * Copyright (C) 2009, 2024-2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide abstract input/output stream interfaces and buffered
 *          stream implementations for use in the javalike library.
 *
 * Features:
 *  - InputStream and OutputStream base classes
 *  - BufferedInputStream and BufferedOutputStream implementations
 *  - Support for available(), read(), write(), flush(), close()
 *
 * Notes:
 *  - Copying of stream classes is explicitly disabled using = delete
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __IO_STREAM_H__
#define __IO_STREAM_H__

#include <string.h>
#include <lang/mutex.h>

namespace io {

    /**
     * @class InputStream
     * @brief Abstract input stream interface.
     */
    class InputStream {
    public:
        InputStream(InputStream const&) = delete;
        InputStream& operator=(InputStream const&) = delete;

    protected:
        inline InputStream() {}
    public:
        virtual ~InputStream() {}

        virtual int available() = 0;
        virtual int read() = 0;
        virtual int read(void* buffer, int len) = 0;
        virtual int close() { return 0; }
        virtual int readFully(char* buffer, int len);
    };

    /**
     * @class BufferedInputStream
     * @brief Buffered input stream implementation.
     */
    class BufferedInputStream : public InputStream {
    public:
        BufferedInputStream(BufferedInputStream const&) = delete;
        BufferedInputStream& operator=(BufferedInputStream const&) = delete;

    private:
        InputStream* in;
        char* buffer;
        int length;
        char* start;
        char* stop;

        int readAhead();
    public:
        BufferedInputStream(InputStream* is, int len = 1412);
        ~BufferedInputStream();
        virtual int available();
        virtual int read();
        virtual int read(void* buffer, int len);
        virtual int close();
    };

    /**
     * @class OutputStream
     * @brief Abstract output stream interface.
     */
    class OutputStream {
    public:
        OutputStream(OutputStream const&) = delete;
        OutputStream& operator=(OutputStream const&) = delete;

    protected:
        inline OutputStream() {}
    public:
        virtual ~OutputStream() {}

        virtual int write(int byte) = 0;
        virtual int write(void const* buffer, int len) = 0;
        virtual int flush();
        virtual int close();
    };

    /**
     * @class BufferedOutputStream
     * @brief Buffered output stream implementation.
     */
    class BufferedOutputStream : public OutputStream {
    public:
        BufferedOutputStream(BufferedOutputStream const&) = delete;
        BufferedOutputStream& operator=(BufferedOutputStream const&) = delete;

    private:
        OutputStream* os;
        char* buffer;
        int length;
        char* start;
        char* const stop;
    protected:
        BufferedOutputStream(OutputStream* os, int sz = 1412);
        ~BufferedOutputStream();
    public:
        virtual int write(int byte);
        virtual int write(void const* buffer, int len);
        virtual int flush();
        virtual int close();
    };

}; // namespace io

#endif /* __IO_STREAM_H__ */
