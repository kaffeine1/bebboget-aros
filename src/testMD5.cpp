/*
 * bebboget MD5 test harness
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
 * Module: MD5 test
 *
 * Purpose:
 *  - Provide a unit test for the MD5 implementation
 *  - Verify correctness against the known test vector "abc"
 *  - Serve as a regression test for digest output
 *
 * Notes:
 *  - MD5 produces a 128-bit (16-byte) digest
 *  - MD5 is cryptographically broken and should not be used for security
 *    purposes; this test is for compatibility and validation only
 *  - Returns 0 on success, non-zero on failure
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

#include <stdint.h>
#include <string.h>

#include "test.h"
#include "md5.h"
#include "unhexlify.h"

int testMD5() {
	unsigned char expected [16];
	unsigned char d[16];

	MD5 md5;
	md5.update("abc", 3);
	md5.digest(d);

	unhexlify(expected, "900150983cd24fb0d6963f7d28e17f72");
	return assertArrayEquals(expected, d, 16);
}

int main() {
	return testMD5() ? 0 : 10;
}
