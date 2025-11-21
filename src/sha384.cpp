/*
 * bebboget SHA-384 implementation (FIPS 180-4)
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
 * Module: SHA-384
 *
 * Purpose:
 *  - Provide a straightforward implementation of SHA-384 as specified in NIST FIPS 180-4
 *  - Support digest(), update(), reset(), and clone() operations
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - SHA-384 produces a 384-bit (48-byte) digest
 *  - SHA-384 is a truncated variant of SHA-512 with different initial state values
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdio.h>
#include "sha384.h"

SHA384::SHA384() : SHA384512(128) {
	reset();
}

/**
 * Initialize new context
 */
void SHA384::reset() {
    state0 = 0xcbbb9d5dc1059ed8LL;
    state1 = 0x629a292a367cd507LL;
    state2 = 0x9159015a3070dd17LL;
    state3 = 0x152fecd8f70e5939LL;
    state4 = 0x67332667ffc00b31LL;
    state5 = 0x8eb44a8768581511LL;
    state6 = 0xdb0c2e0d64f98fa7LL;
    state7 = 0x47b5481dbefa4fa4LL;
	/**/
	count = 0;
}

void SHA384::__getDigest(unsigned char *to) {
	*to++ = state0 >> 56;
	*to++ = state0 >> 48;
	*to++ = state0 >> 40;
	*to++ = state0 >> 32;
	*to++ = state0 >> 24;
	*to++ = state0 >> 16;
	*to++ = state0 >> 8;
	*to++ = state0;
	*to++ = state1 >> 56;
	*to++ = state1 >> 48;
	*to++ = state1 >> 40;
	*to++ = state1 >> 32;
	*to++ = state1 >> 24;
	*to++ = state1 >> 16;
	*to++ = state1 >> 8;
	*to++ = state1;
	*to++ = state2 >> 56;
	*to++ = state2 >> 48;
	*to++ = state2 >> 40;
	*to++ = state2 >> 32;
	*to++ = state2 >> 24;
	*to++ = state2 >> 16;
	*to++ = state2 >> 8;
	*to++ = state2;
	*to++ = state3 >> 56;
	*to++ = state3 >> 48;
	*to++ = state3 >> 40;
	*to++ = state3 >> 32;
	*to++ = state3 >> 24;
	*to++ = state3 >> 16;
	*to++ = state3 >> 8;
	*to++ = state3;
	*to++ = state4 >> 56;
	*to++ = state4 >> 48;
	*to++ = state4 >> 40;
	*to++ = state4 >> 32;
	*to++ = state4 >> 24;
	*to++ = state4 >> 16;
	*to++ = state4 >> 8;
	*to++ = state4;
	*to++ = state5 >> 56;
	*to++ = state5 >> 48;
	*to++ = state5 >> 40;
	*to++ = state5 >> 32;
	*to++ = state5 >> 24;
	*to++ = state5 >> 16;
	*to++ = state5 >> 8;
	*to++ = state5;
}

unsigned SHA384::len() const {
	return 48;
}

MessageDigest * SHA384::clone() const {
	return new SHA384(*this);
}
