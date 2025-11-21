/*
 * bebboget SHA-1 test harness
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
 * Module: SHA-1 test
 *
 * Purpose:
 *  - Provide a unit test for the SHA-1 implementation
 *  - Verify correctness against the known test vector "abc"
 *  - Serve as a regression test for digest output
 *
 * Notes:
 *  - SHA-1 produces a 160-bit (20-byte) digest
 *  - SHA-1 is cryptographically broken and should not be used for security
 *    purposes; this test is for compatibility and validation only
 *  - Returns 0 on success, non-zero on failure
 *  - Designed for Amiga and cross-platform builds
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
#include "sha.h"
#include "unhexlify.h"

int testSHA() {
	puts("testSHA");
	unsigned char expected [20];
	SHA sha;
	unsigned char d[20];

	sha.update("abc", 3);
	sha.digest(d);
	unhexlify(expected, "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d");
	return assertArrayEquals(expected, d, 20);
}

int main() {
	return testSHA() ? 0 : 10;
}
