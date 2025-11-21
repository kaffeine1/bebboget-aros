/*
 * javalike stream I/O abstraction
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
 * Module: stream.cpp
 *
 * Purpose:
 *  - Provide abstract InputStream and OutputStream classes
 *  - Implement buffered stream wrappers for efficient I/O
 *  - Support readFully(), buffering, flushing, and closing operations
 *
 * Notes:
 *  - BufferedInputStream caches data from an underlying InputStream
 *  - BufferedOutputStream accumulates writes before flushing to OutputStream
 *  - Designed for Amiga and cross-platform builds
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <stdint.h>
#include "io/stream.h"

using namespace io;

int InputStream::readFully(char * buffer, int len) {
  int total = 0;
  for (;;) {
    int sz = read(buffer, len - total);
    if (sz <= 0) {
      return total ? total : -1;
    }
    total += sz;
    if (len == total)
      break;
    buffer += sz;
  }
  return len;
}

BufferedInputStream::BufferedInputStream(InputStream * is, int len) :
  in(is), buffer(new char[len]), length(len), start(buffer), stop(buffer) {
}

BufferedInputStream::~BufferedInputStream() {
  close();
  delete in;
}

int BufferedInputStream::available(){
  int avail = stop - start;
  if (avail)
    return avail;
  if (in->available() > 0)
    readAhead();
  return stop - start;
}

int BufferedInputStream::read() {
  if (start == stop) {
    readAhead();
    if (start == stop)
      return -1;
  }
  return 0xff & *start++;
}

int BufferedInputStream::read(void * buffer, int len) {
  if (start == stop) {
    readAhead();
    if (start == stop)
      return 0;
  }
  int avail = stop - start;
  if (len > avail)
    len = avail;
  memcpy(buffer, start, len);
  start += len;
  return len;
}

int BufferedInputStream::close() {
  return in->close();
}

int BufferedInputStream::readAhead() {
  start = buffer;
  int len = in->read(buffer, length);
  if (len < 0) {
    stop = buffer;
    return false;
  }
  stop = start + len;
  return true;
}

int OutputStream::flush() {
  return 0;
}

int OutputStream::close() {
  return flush();
}

BufferedOutputStream::BufferedOutputStream(OutputStream * os_, int sz) :
  os(os_), buffer(new char[sz]), length(sz), start(buffer + sz), stop(buffer + sz) {
}

BufferedOutputStream::~BufferedOutputStream() {
  close();
  delete[] buffer;
}

int BufferedOutputStream::write(int byte) {
  if (start == stop) {
    if (flush())
      return -1;
    if (start == stop)
      return -1;
  }
  *start++ = (char) byte;
  if (start == stop)
    return flush();
  return 1;
}

int BufferedOutputStream::write(void const * buffer_, int len) {
	uint8_t *buffer = (uint8_t *)buffer_;
  for (int i = 0; i < len; ++i) {
	  int r = write(*buffer++);
	  if (r < 0)
		  return r;
  }
  return len;
}

int BufferedOutputStream::flush() {
  int used = start - buffer;
  if (used) {
    if (os->write(buffer, used))
		return -1;
	start = buffer;
  }
  return 0;
}

int BufferedOutputStream::close() {
  return os->close();
}
