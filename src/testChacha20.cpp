/*
 * bebboget ChaCha20 / Poly1305 test harness
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
 * Module: ChaCha20/Poly1305 tests
 *
 * Purpose:
 *  - Provide unit tests for ChaCha20 stream generation and Poly1305 MAC
 *  - Verify correctness against known test vectors and edge cases
 *  - Serve as regression tests for AEAD ChaCha20-Poly1305 components
 *
 * Notes:
 *  - Uses fixed vectors (RFC 7539-style and custom edge cases)
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

#include "chacha20poly1305.h"
#include "fastmath32.h"

int testChaCha20() {
	puts("testChaCha20");

	uint8_t key[32];
	unhexlify(key, "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:"
			"10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");

	uint8_t nonce[12];
	unhexlify(nonce, "00:00:00:00:00:00:00:4a:00:00:00:00");

	ChaCha20 cc;
	cc.setKey(key, sizeof(key));
	cc.setNonce(nonce, sizeof(nonce));

	cc.nextBlock();

	uint8_t block1[64];
	unhexlify(block1, "22 4F 51 F3 40 1B D9 E1  2F DE 27 6F B8 63 1D ED"
			"8C 13 1F 82 3D 2C 06 E2  7E 4F CA EC 9E F3 CF 78"
			"8A 3B 0A A3 72 60 0A 92  B5 79 74 CD ED 2B 93 34"
			"79 4C BA 40 C6 3E 34 CD  EA 21 2C 4C F0 7D 41 B7");

	int r = assertArrayEquals(block1, cc.getStream(), 64);

	cc.nextBlock();
	uint8_t block2[64];
	unhexlify(block2, "69 A6 74 9F 3F 63 0F 41  22 CA FE 28 EC 4D C4 7E"
			"26 D4 34 6D 70 B9 8C 73  F3 E9 C5 3A C4 0C 59 45"
			"39 8B 6E DA 1A 83 2C 89  C1 67 EA CD 90 1D 7E 2B"
			"F3 63 74 03 73 20 1A A1  88 FB BC E8 39 91 C4 ED");

	r &= assertArrayEquals(block2, cc.getStream(), 64);

	memset(key, 0, sizeof(key));
	memset(nonce, 0, sizeof(nonce));
	cc.setKey(key, sizeof(key));
	cc.setNonce(nonce, sizeof(nonce));
	cc.nextBlock();
	uint8_t test1[64];
	unhexlify(test1,	"9F 07 E7 BE 55 51 38 7A  98 BA 97 7C 73 2D 08 0D "
			"CB 0F 29 A0 48 E3 65 69  12 C6 53 3E 32 EE 7A ED"
			"29 B7 21 76 9C E6 4E 43  D5 71 33 B0 74 D8 39 D5 "
			"31 ED 1F 28 51 0A FB 45  AC E1 0A 1F 4B 79 4D 6F");
	r &= assertArrayEquals(test1, cc.getStream(), 64);



	uint8_t key1[32];
	unhexlify(key1,
			"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
			"90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
	uint8_t nonce1[12] = { 0x07, 0, 0, 0,
			0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47,
	};
	cc.setKey(key1, sizeof(key1));
	cc.setNonce(nonce1, sizeof(nonce1));
	cc.zeroCounter();
	cc.nextBlock();

	uint8_t exp1[32];
	unhexlify(exp1,
			"7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84"
			"0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff"
			);
	r &= assertArrayEquals(exp1, cc.getStream(), 32);

	return r;
}

int testPoly1305() {
	puts("testPoly1305");

//	uint8_t message[34];
//	/* Message to be Authenticated: */
//	unhexlify(message, "43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f"
//			"72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f"
//			"75 70");
//
//	uint8_t key[32];
//	unhexlify(key, "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8"
//			"01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
//
//	Poly1305 poly;
//	poly.setKey(key, sizeof(key));
//	poly.update(message, sizeof(message));

	uint8_t res[16];

	// test 1
	uint8_t key1[32]; memset(key1, 0, sizeof(key1));
	uint8_t text1[64]; memset(text1, 0, sizeof(text1));
	uint8_t exp1[16]; memset(exp1, 0, sizeof(exp1));
	Poly1305 poly;
	poly.setKey(key1, sizeof(key1));
	poly.update(text1, sizeof(text1));
	poly.digest(res);

	int r = assertArrayEquals(exp1, res, 16);

	uint8_t key2[32];
	unhexlify(key2,
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"
			);
	uint8_t text2[368 + 7];
	unhexlify(text2,
			   "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74 "
			   "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e "
			   "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72 "
			   "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69 "
			   "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72 "
			   "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46 "
			   "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20 "
			   "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73 "
			   "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69 "
			   "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74 "
			   "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69 "
			   "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72 "
			   "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74 "
			   "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20 "
			   "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75 "
			   "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e "
			   "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69 "
			   "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20 "
			   "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63 "
			   "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61 "
			   "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e "
			   "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c "
			   "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65"
			   "73 73 65 64 20 74 6f"
);

	uint8_t exp2[16];
	unhexlify(exp2, "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e");

	poly.setKey(key2, sizeof(key2));
	poly.update(text2, sizeof(text2));
	poly.digest(res);

	r &= assertArrayEquals(exp2, res, 16);


	uint8_t key3[32];
	unhexlify(key3,
			"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 "
			"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
			);
	uint8_t text3[112 + 15];
	unhexlify(text3,
			   "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61"
			   "6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f"
			   "76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64"
			   "20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77"
			   "61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77"
			   "65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65"
			   "73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20"
			   "72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e" );

	uint8_t exp3[16];
	unhexlify(exp3, "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62 ");

	poly.setKey(key3, sizeof(key3));
	poly.update(text3, sizeof(text3));
	poly.digest(res);

	r &= assertArrayEquals(exp3, res, 16);


	// If one uses 130-bit partial reduction, does the code
    // handle the case where partially reduced final result is not fully
    // reduced?
	uint8_t key4[32];
	unhexlify(key4,
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text4[16];
	unhexlify(text4,
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
	);

	uint8_t exp4[16];
	unhexlify(exp4, "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key4, sizeof(key4));
	poly.update(text4, sizeof(text4));
	poly.digest(res);
	r &= assertArrayEquals(exp4, res, 16);

	// What happens if addition of s overflows modulo 2^128?
	uint8_t key5[32];
	unhexlify(key5,
			"02 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			);
	uint8_t text5[16];
	unhexlify(text5,
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
	);

	uint8_t exp5[16];
	unhexlify(exp5, "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key5, sizeof(key5));
	poly.update(text5, sizeof(text5));
	poly.digest(res);
	r &= assertArrayEquals(exp5, res, 16);

	// What happens if data limb is all ones and there is carry from lower limb?
	uint8_t key6[32];
	unhexlify(key6,
			"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text6[48];
	unhexlify(text6,
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			"f0 ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			"11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
	);

	uint8_t exp6[16];
	unhexlify(exp6, "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key6, sizeof(key6));
	poly.update(text6, sizeof(text6));
	poly.digest(res);
	r &= assertArrayEquals(exp6, res, 16);


	// What happens if final result from polynomial part is exactly 2^130-5?
	uint8_t key7[32];
	unhexlify(key7,
			"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text7[48];
	unhexlify(text7,
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			"fb fe fe fe fe fe fe fe  fe fe fe fe fe fe fe fe"
			"01 01 01 01 01 01 01 01  01 01 01 01 01 01 01 01"
	);

	uint8_t exp7[16];
	unhexlify(exp7, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key7, sizeof(key7));
	poly.update(text7, sizeof(text7));
	poly.digest(res);
	r &= assertArrayEquals(exp7, res, 16);

	// What happens if final result from polynomial part is exactly 2^130-6?
	uint8_t key8[32];
	unhexlify(key8,
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text8[16];
	unhexlify(text8,
			"fd ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
	);

	uint8_t exp8[16];
	unhexlify(exp8, "fa ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff");

	poly.setKey(key8, sizeof(key8));
	poly.update(text8, sizeof(text8));
	poly.digest(res);
	r &= assertArrayEquals(exp8, res, 16);

	//  What happens if 5*H+L-type reduction produces 131-bit final result?
	uint8_t key9[32];
	unhexlify(key9,
			"01 00 00 00 00 00 00 00  04 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"
			);
	uint8_t text9[48];
	unhexlify(text9,
		"E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00"
		   "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00"
		   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"	);

	uint8_t exp9[16];
	unhexlify(exp9, "13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key9, sizeof(key9));
	poly.update(text9, sizeof(text9));
	poly.digest(res);
	r &= assertArrayEquals(exp9, res, 16);

	// from tls
	uint8_t pkey[32];
	unhexlify(pkey,
			"EA 16 55 AB 23 7E F8 A0  93 C2 5B 81 26 9B B5 B9"
			"71 76 01 88 37 C0 69 F0  52 3F B3 FD 30 09 FB 7C"
			);

	Poly1305 pl;
	pl.setKey(pkey, 32);

	uint8_t d[16];
	unhexlify(d,
			"17 03 03 00 1B 00 00 00  00 00 00 00 00 00 00 00"
			);
	pl.update(d, 16);

	unhexlify(d,
			"96 C4 DC 19 11 C9 43 58  F0 E5 2A 00 00 00 00 00"
			);
	pl.update(d, 16);

	unhexlify(d,
			"05 00 00 00 00 00 00 00  0B 00 00 00 00 00 00 00"
			);
	pl.update(d, 16);

	uint8_t to[16];
	pl.digest(to);

	uint8_t x[16];
	unhexlify(x,
			"29 09 80 EE 1B 01 DC 15  CA 5D 71 B0 2C A5 19 30");

	r &= assertArrayEquals(x, to, 16);

	return r;
}

int testChaCha20Poly1305() {
	puts("testChaCha20Poly1305");


	uint8_t key[32];
	unhexlify(key,
			"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 "
			"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
			);

	uint8_t clear[256 + 9];
	unhexlify(clear,
			 "49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20"
			 "61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65"
			 "6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20"
			 "6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d"
			 "6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65"
			 "20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63"
			 "65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64"
			 "20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65"
			 "6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e"
			 "20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72"
			 "69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65"
			 "72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72"
			 "65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61"
			 "6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65"
			 "6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20"
			 "2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67"
			 "72 65 73 73 2e 2f e2 80 9d"
	);

	uint8_t nonce[12];
	unhexlify(nonce,
			"00 00 00 00 01 02 03 04 05 06 07 08 "
			);

	uint8_t aad[12];
	unhexlify(aad,
			"f3 33 88 86 00 00 00 00 00 00 4e 91"
			);

	uint8_t cipher[sizeof(clear)];
	uint8_t tag[16];

	ChaCha20Poly1305 ccp;
	ccp.setKey(key, 32);
	ccp.init(nonce, 12);
	ccp.updateHash(aad, 12);
	ccp.encrypt(cipher, clear, sizeof(clear));
	ccp.calcHash(tag);
//	_dump("tag", tag, 16);

	uint8_t exp[16];
	unhexlify(exp, "ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38");

	int r = assertArrayEquals(exp, tag, 16);

	// decrypt again
	ccp.setKey(key, 32);
	ccp.init(nonce, 12);
	ccp.updateHash(aad, 12);
	ccp.decrypt(cipher, cipher, sizeof(cipher));
	ccp.calcHash(tag);

	r &= assertArrayEquals(clear, cipher, sizeof(cipher));
	r &= assertArrayEquals(exp, tag, 16);

	return r;
}

int main() {
	return testChaCha20() & testPoly1305() & testChaCha20Poly1305() ? 0 : 10;
}
