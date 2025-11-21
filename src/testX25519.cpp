/*
 * bebboget Ed25519 / X25519 test harness
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
 * Module: Ed25519 / X25519 tests
 *
 * Purpose:
 *  - Provide unit tests for Ed25519 field arithmetic (add, square, multiply)
 *  - Verify special constant multiplication (121665) used in curve operations
 *  - Test X25519 scalar multiplication for Diffie-Hellman key exchange
 *  - Serve as regression tests for elliptic curve cryptographic routines
 *
 * Notes:
 *  - Uses fixed test vectors for Ed25519 and X25519
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
#include "unhexlify.h"

#include <bytearray.h>
#include <ed25519i.h>

int testAdd() {
	puts("testAdd");
	bytes(in, 32);
	unhexlify(in.begin(),
			"7f 00 00 03 00 00 00 00"
			"0f 00 00 03 00 00 00 00"
			"0f 00 00 03 00 80 00 00"
			"00 00 07 00 00 00 00 7f"
			);
	ed_t a[EDSIZE];
	unpack16(a, in.begin());

	ed_t r[EDSIZE];
	edadd(r, a, a);

	bytes(out, 32);
	pack16(out.begin(), r);

	bytes(ex, 32);
	unhexlify(ex.begin(),
			"11 01 00 06 00 00 00 00"
			"1e 00 00 06 00 00 00 00"
			"1e 00 00 06 00 00 01 00"
			"00 00 0e 00 00 00 00 7e"
			);

	return assertArrayEquals(ex.begin(), out.begin(), out.size());
}

int testSquare() {
	puts("testSquare");
	bytes(ain, 32);
	unhexlify(ain.begin(),
//			"01 20 78 ef 2d e7 00 00"
//			"00 00 00 41 00 00 00 00"
//			"01 00 f0 00 00 00 77 00"
//			"00 c6 00 00 9b 14 00 7f"
			"80 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00"
			"80 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 01"
			);
	ed_t a[EDSIZE];
	unpack16(a, ain.begin());


	ed_t r[EDSIZE];
	edsquare(r, a);

	bytes(out, 32);
	pack16(out.begin(), r);

	ed_t rx[EDSIZE];
	edmul(rx, a, a);

	bytes(ex, 32);
	pack16(ex.begin(), rx);

	return assertArrayEquals(ex.begin(), out.begin(), out.size());
}


int testMul() {
	puts("testMul");
	bytes(ain, 32);
	unhexlify(ain.begin(),
			"52 33 DF 72 CE DE 08 F6"
			"B4 99 A8 13 95 C1 B2 A2"
			"C7 66 3A 7C D4 03 CA 3A"
			"AE E6 7E 63 FE DA 09 2E"
			);
	ed_t a[EDSIZE];
	unpack16(a, ain.begin());

	bytes(bin, 32);
	unhexlify(bin.begin(),
			"92 45 A0 25 47 5F A2 6B"
			"4C 67 D0 88 DE 89 EB 6B"
			"76 9A D4 83 0C DA 7F CA"
			"90 02 6A 31 8A 6A DD 5E"
			);
	ed_t b[EDSIZE];
	unpack16(b, bin.begin());

	ed_t r[EDSIZE];
	edmul(r, a, b);

	bytes(out, 32);
	pack16(out.begin(), r);

	bytes(ex, 32);
	unhexlify(ex.begin(),
			"C3 69 9D 4A 09 37 1D D9"
			"4F 4E C9 65 67 80 88 99"
			"24 53 33 51 16 3F 1E 9A"
			"D0 BD 8B B6 F5 2F A0 38"
			);

	return assertArrayEquals(ex.begin(), out.begin(), out.size());
}

extern "C" void edmul121665(ed_t *out, const ed_t *a);
int testMul121665() {
	puts("testMul121665");
	bytes(ain, 32);
	unhexlify(ain.begin(),
			"38 8D FA 35 BC 1A 8C E7  2B D6 54 24 F4 03 8E 59"
			"17 55 C6 7D 6C 85 01 1A  C0 A5 66 75 2A 03 DA 5D"
			);
	ed_t a[EDSIZE];
	unpack16(a, ain.begin());


	ed_t r[EDSIZE];
	edmul121665(r, a);

	bytes(out, 32);
	memset(out.begin(), 0, 32);
	pack16(out.begin(), r);

	bytes(ex, 32);
	unhexlify(ex.begin(),
			"FA 9F BE 98 F1 01 2E C0  C6 D7 ED A2 66 00 65 3E"
			"18 EE 3D EF EA 2D F3 6C  07 86 9B 44 9D 95 3A 58"
			);

	return assertArrayEquals(ex.begin(), out.begin(), out.size());
}


extern "C"
void fe_scalarmult_x25519(uint8_t *to, const uint8_t *scalar, const uint8_t *base);

int testFe_scalarmult_x25519() {
	puts("testFe_scalarmult_x25519");

	bytes(dhg, 32);
	unhexlify(dhg.begin(),
			"C9 9D F6 5E DD CB 8A C0  EC E8 33 3E 6B EE C7 66"
			"70 4A A4 4F B6 E2 09 F0  EA 6D 71 09 62 05 CF 41"
			);


	bytes(priv, 32);
	unhexlify(priv.begin(),
			"E8 FE 1A 59 1A F2 8B F2  AB 1A 1D FD 9B D2 ED B9"
			"0E CE 9F A3 E2 2B BF B7  2E 9C 10 0E 43 08 A6 4B"
			);

	bytes(preMasterSecret, 32);
	fe_scalarmult_x25519(preMasterSecret.begin(), priv.begin(), dhg.begin());


	bytes(ex, 32);
	unhexlify(ex.begin(),
			"52 33 DF 72 CE DE 08 F6  B4 99 A8 13 95 C1 B2 A2"
			"C7 66 3A 7C D4 03 CA 3A  AE E6 7E 63 FE DA 09 2E"
			);

	return assertArrayEquals(ex.begin(), preMasterSecret.begin(), preMasterSecret.size());

}

int main() {
	return	testSquare()
			& testAdd()
			& testMul()
			& testMul121665()
			& testFe_scalarmult_x25519()
			? 0 : 10;
}
