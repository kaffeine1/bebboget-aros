/*
 * bebboget SHA-1 implementation (FIPS 180-1)
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
 * Module: SHA-1
 *
 * Purpose:
 *  - Provide a straightforward implementation of SHA-1
 *  - Support digest(), update(), reset(), and clone() operations
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - SHA-1 produces a 160-bit (20-byte) digest
 *  - SHA-1 is considered cryptographically broken; use only for legacy compatibility
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include "sha.h"


inline void SHA::blk() {
	int i = 0;
	for (; i < 3; ++i)
		block[i] = rol(block[i + 17] ^ block[i + 12] ^ block[i + 6] ^ block[i + 4], 1);
	for (; i < 8; ++i)
		block[i] = rol(block[i - 3] ^ block[i + 12] ^ block[i + 6] ^ block[i + 4], 1);
	for (; i < 14; ++i)
		block[i] = rol(block[i - 3] ^ block[i - 8] ^ block[i + 6] ^ block[i + 4], 1);
	for (; i < 16; ++i)
		block[i] = rol(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i + 4], 1);
	for (; i < 20; ++i)
		block[i] = rol(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16], 1);
}

SHA::SHA() :
		MessageDigest(64) {
	reset();
}

/**
 * Initialize new context
 */
void SHA::reset() {
	state0 = 0x67452301;
	state1 = 0xEFCDAB89;
	state2 = 0x98BADCFE;
	state3 = 0x10325476;
	state4 = 0xC3D2E1F0;

	count = 0;
}

void SHA::transform() {
	int i = 0;

	// convert to int
	for (int j = 0; i < 16; j += 4) {
		block[i++] = ((data[j]) << 24) | ((data[j + 1] & 0xff) << 16) | ((data[j + 2] & 0xff) << 8) | ((data[j + 3] & 0xff));
	}

	for (; i < 20; ++i) {
		block[i] = rol(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16], 1);
	}

	/* Copy context->state[] to working vars */
	t0 = state0;
	t1 = state1;
	t2 = state2;
	t3 = state3;
	t4 = state4;

	i = 0;
	add = 0x5A827999;
	for (;;) {
		R00(((t1 & (t2 ^ t3)) ^ t3), block[i++]);
		R04(((t0 & (t1 ^ t2)) ^ t2), block[i++]);
		R03(((t4 & (t0 ^ t1)) ^ t1), block[i++]);
		R02(((t3 & (t4 ^ t0)) ^ t0), block[i++]);
		R01(((t2 & (t3 ^ t4)) ^ t4), block[i++]);
		if (i == 20)
			break;
	}

	add = 0x6ED9EBA1;
	blk();

	for (i = 0;;) {
		R00((t1 ^ t2 ^ t3), block[i++]);
		R04((t0 ^ t1 ^ t2), block[i++]);
		R03((t4 ^ t0 ^ t1), block[i++]);
		R02((t3 ^ t4 ^ t0), block[i++]);
		R01((t2 ^ t3 ^ t4), block[i++]);
		if (i == 20)
			break;
	}
	/*
	 * ((a + b) * c) + (a * b) = (ac + bc + ab)
	 *     4 ops					5 ops
	 * ac + b(a+c) = (a+b)c + ab = (b+c)a + bc
	 */
	add = 0x8F1BBCDC;
	blk();

	for (i = 0;;) {
		R00((((t1 | t2) & t3) | (t1 & t2)), block[i++]);
		R04((((t0 | t1) & t2) | (t0 & t1)), block[i++]);
		R03((((t4 | t0) & t1) | (t4 & t0)), block[i++]);
		R02((((t3 | t4) & t0) | (t3 & t4)), block[i++]);
		R01((((t2 | t3) & t4) | (t2 & t3)), block[i++]);
		if (i == 20)
			break;
	}

	add = 0xCA62C1D6;
	blk();
	for (i = 0;;) {
		R00((t1 ^ t2 ^ t3), block[i++]);
		R04((t0 ^ t1 ^ t2), block[i++]);
		R03((t4 ^ t0 ^ t1), block[i++]);
		R02((t3 ^ t4 ^ t0), block[i++]);
		R01((t2 ^ t3 ^ t4), block[i++]);
		if (i == 20)
			break;
	}
	/* Add the working vars back into context.state[] */
	state0 += t0;
	state1 += t1;
	state2 += t2;
	state3 += t3;
	state4 += t4;
}

void SHA::__getDigest(unsigned char *to) {
	*to++ = state0 >> 24;
	*to++ = state0 >> 16;
	*to++ = state0 >> 8;
	*to++ = state0;
	*to++ = state1 >> 24;
	*to++ = state1 >> 16;
	*to++ = state1 >> 8;
	*to++ = state1;
	*to++ = state2 >> 24;
	*to++ = state2 >> 16;
	*to++ = state2 >> 8;
	*to++ = state2;
	*to++ = state3 >> 24;
	*to++ = state3 >> 16;
	*to++ = state3 >> 8;
	*to++ = state3;
	*to++ = state4 >> 24;
	*to++ = state4 >> 16;
	*to++ = state4 >> 8;
	*to++ = state4;
}

unsigned SHA::len() const {
	return 20;
}

MessageDigest * SHA::clone() const {
	return new SHA(*this);
}
