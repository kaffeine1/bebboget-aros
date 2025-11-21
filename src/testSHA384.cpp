/*
 * bebboget SHA-384 test harness
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
 * Module: SHA-384 test
 *
 * Purpose:
 *  - Provide unit tests for the SHA-384 implementation
 *  - Verify correctness against the known test vector
 *    "The quick brown fox jumps over the lazy dog"
 *  - Verify HMAC-SHA384 output against a fixed test vector
 *  - Serve as regression tests for digest and HMAC routines
 *
 * Notes:
 *  - SHA-384 produces a 384-bit (48-byte) digest
 *  - HMAC-SHA384 is tested with zeroed input and key
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
#include "sha384.h"
#include "unhexlify.h"


int testSHA384() {
	puts("testSHA384");
	SHA384 sha384;
	char const *txt = "The quick brown fox jumps over the lazy dog";
	unsigned char EXPECTED1[48];
	unhexlify(EXPECTED1,
			"CA 73 7F 10 14 A4 8F 4C  0B 6D D4 3C B1 77 B0 AF"
			"D9 E5 16 93 67 54 4C 49  40 11 E3 31 7D BF 9A 50"
			"9C B1 E5 DC 1E 85 A9 41  BB EE 3D 7F 2A FB C9 B1");

	unsigned char d[48];
	sha384.update(txt, strlen(txt));
	sha384.digest(d);
	return assertArrayEquals(EXPECTED1, d, 48);
}

int testHMAC() {
	SHA384 sha384;

	static uint8_t NULLBYTES[48];

	unsigned char EXPECTED1[48];
	unhexlify(EXPECTED1,
			"7E E8 20 6F 55 70 02 3E  6D C7 51 9E B1 07 3B C4"
			"E7 91 AD 37 B5 C3 82 AA  10 BA 18 E2 35 7E 71 69"
			"71 F9 36 2F 2C 2F E2 A7  6B FD 78 DF EC 4E A9 B5");

	unsigned char d[48];
	sha384.hmac(d, NULLBYTES, 1, NULLBYTES, 48, 0);
	return assertArrayEquals(EXPECTED1, d, 48);
}

int main() {
	return testSHA384() & testHMAC() ? 0 : 10;
}
