/*
 * bebboget MD5 implementation
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
 * Module: MD5
 *
 * Purpose:
 *  - Provide a straightforward implementation of MD5 as specified in RFC 1321
 *  - Support digest(), update(), reset(), and clone() operations
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 *  - MD5 is considered cryptographically broken; use only for legacy compatibility
 * ----------------------------------------------------------------------
 */

#include "md5.h"

#include <stdio.h>

MD5::MD5() : MessageDigest(64) {
	reset();
}

MD5::~MD5() {}
/**
 * Initialize new context
 */
void MD5::reset() {
	state0 = 1732584193;
	state1 = -271733879;
	state2 = -1732584194;
	state3 = 271733878;
	/**/
	count = 0;
}

void MD5::addBitCount(uint64_t bitCount) {
	for (int i = 56; i < 64; ++i) {
		data[i] = bitCount;
		bitCount >>= 8;
	}
}

void MD5::transform() {
	// convert to int
	for (short j = 0, i = 0; i < 16; j += 4) {
		block[i] = ((data[j] & 0xff)) | ((data[j + 1] & 0xff) << 8) | ((data[j + 2] & 0xff) << 16) | ((data[j + 3]) << 24);
		++i;
	}

	t0 = state0;
	t1 = state1;
	t2 = state2;
	t3 = state3;


	G0(F00(), block[0], 7, 0xd76aa478);
	G3(F03(), block[1], 12, 0xe8c7b756);
	G2(F02(), block[2], 17, 0x242070db);
	G1(F01(), block[3], 22, 0xc1bdceee);


//    HashTest.dump(new int[]{t0, t1, t2, t3});
//    HashTest.dump(block);

	G0(F00(), block[4], 7, 0xf57c0faf);
	G3(F03(), block[5], 12, 0x4787c62a);
	G2(F02(), block[6], 17, 0xa8304613);
	G1(F01(), block[7], 22, 0xfd469501);
	G0(F00(), block[8], 7, 0x698098d8);
	G3(F03(), block[9], 12, 0x8b44f7af);
	G2(F02(), block[10], 17, 0xffff5bb1);
	G1(F01(), block[11], 22, 0x895cd7be);
	G0(F00(), block[12], 7, 0x6b901122);
	G3(F03(), block[13], 12, 0xfd987193);
	G2(F02(), block[14], 17, 0xa679438e);
	G1(F01(), block[15], 22, 0x49b40821);

	G0(F10(), block[1], 5, 0xf61e2562);

	G3(F13(), block[6], 9, 0xc040b340);
	G2(F12(), block[11], 14, 0x265e5a51);

	G1(F11(), block[0], 20, 0xe9b6c7aa);
	G0(F10(), block[5], 5, 0xd62f105d);
	G3(F13(), block[10], 9, 0x2441453);
	G2(F12(), block[15], 14, 0xd8a1e681);

	G1(F11(), block[4], 20, 0xe7d3fbc8);
	G0(F10(), block[9], 5, 0x21e1cde6);
	G3(F13(), block[14], 9, 0xc33707d6);

	G2(F12(), block[3], 14, 0xf4d50d87);
	G1(F11(), block[8], 20, 0x455a14ed);
	G0(F10(), block[13], 5, 0xa9e3e905);

	G3(F13(), block[2], 9, 0xfcefa3f8);
	G2(F12(), block[7], 14, 0x676f02d9);
	G1(F11(), block[12], 20, 0x8d2a4c8a);

	G0(F20(), block[5], 4, 0xfffa3942);
	G3(F23(), block[8], 11, 0x8771f681);
	G2(F22(), block[11], 16, 0x6d9d6122);
	G1(F21(), block[14], 23, 0xfde5380c);

	G0(F20(), block[1], 4, 0xa4beea44);
	G3(F23(), block[4], 11, 0x4bdecfa9);
	G2(F22(), block[7], 16, 0xf6bb4b60);
	G1(F21(), block[10], 23, 0xbebfbc70);
	G0(F20(), block[13], 4, 0x289b7ec6);

	G3(F23(), block[0], 11, 0xeaa127fa);
	G2(F22(), block[3], 16, 0xd4ef3085);
	G1(F21(), block[6], 23, 0x4881d05);
	G0(F20(), block[9], 4, 0xd9d4d039);
	G3(F23(), block[12], 11, 0xe6db99e5);
	G2(F22(), block[15], 16, 0x1fa27cf8);

	G1(F21(), block[2], 23, 0xc4ac5665);

	G0(F30(), block[0], 6, 0xf4292244);
	G3(F33(), block[7], 10, 0x432aff97);
	G2(F32(), block[14], 15, 0xab9423a7);

	G1(F31(), block[5], 21, 0xfc93a039);
	G0(F30(), block[12], 6, 0x655b59c3);

	G3(F33(), block[3], 10, 0x8f0ccc92);
	G2(F32(), block[10], 15, 0xffeff47d);

	G1(F31(), block[1], 21, 0x85845dd1);
	G0(F30(), block[8], 6, 0x6fa87e4f);
	G3(F33(), block[15], 10, 0xfe2ce6e0);

	G2(F32(), block[6], 15, 0xa3014314);
	G1(F31(), block[13], 21, 0x4e0811a1);

	G0(F30(), block[4], 6, 0xf7537e82);
	G3(F33(), block[11], 10, 0xbd3af235);

	G2(F32(), block[2], 15, 0x2ad7d2bb);
	G1(F31(), block[9], 21, 0xeb86d391);

	state0 += t0;
	state1 += t1;
	state2 += t2;
	state3 += t3;
}

void MD5::__getDigest(uint8_t *r) {
	*r++ = (state0);
	*r++ = (state0 >> 8);
	*r++ = (state0 >> 16);
	*r++ = (state0 >> 24);
	*r++ = (state1);
	*r++ = (state1 >> 8);
	*r++ = (state1 >> 16);
	*r++ = (state1 >> 24);
	*r++ = (state2);
	*r++ = (state2 >> 8);
	*r++ = (state2 >> 16);
	*r++ = (state2 >> 24);
	*r++ = (state3);
	*r++ = (state3 >> 8);
	*r++ = (state3 >> 16);
	*r++ = (state3 >> 24);
}


unsigned MD5::len() const {
	return 16;
}

MessageDigest * MD5::clone() const {
	return new MD5(*this);
}
