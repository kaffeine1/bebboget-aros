/*
 * bebboget SHA-256 test harness
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
 * Module: SHA-256 test
 *
 * Purpose:
 *  - Provide a unit test for the SHA-256 implementation
 *  - Verify correctness against the known test vector
 *    "The quick brown fox jumps over the lazy dog"
 *  - Serve as a regression test for digest output
 *
 * Notes:
 *  - SHA-256 produces a 256-bit (32-byte) digest
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
#include "sha256.h"
#include "unhexlify.h"


int testSHA256() {
	puts("testSHA256");
	SHA256 sha256;
	char const *txt = "The quick brown fox jumps over the lazy dog";
	static unsigned char const EXPECTED1[] = { 0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51,
			0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92 };

	unsigned char d[32];
	sha256.update(txt, strlen(txt));
	sha256.digest(d);
	return assertArrayEquals(EXPECTED1, d, 32);
}

int main() {
	return testSHA256() ? 0 : 10;
}
