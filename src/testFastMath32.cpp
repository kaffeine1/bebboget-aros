/*
 * bebboget FastMath32 / BigInteger / Secp256r1 test harness
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
 * Module: FastMath32 / BigInteger / Secp256r1 tests
 *
 * Purpose:
 *  - Provide unit tests for low-level arithmetic routines (conversion, add, sub, mul, square)
 *  - Verify modular arithmetic (xmod, modInverse, bitLength)
 *  - Test RSA modular exponentiation and elliptic curve signature verification (secp256r1)
 *  - Serve as regression tests for cryptographic primitives
 *
 * Notes:
 *  - Uses known test vectors for RSA and ECDSA/secp256r1
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

#include "fastmath32.h"
#include "biginteger.h"
#include "sha256.h"
#include "secp256r1.h"

int testConversion() {
	bytes(in, 16);
	unhexlify(in.begin(), "0f 00 00 03 00 00 00 00"
			"00 00 07 00 00 00 00 02");

	uinta r = FastMath32::byte2Int(in, 4);
	bytea b = FastMath32::int2Byte(r, 16);

	return assertArrayEquals(in.begin(), b.begin(), 16);
}

int testAdd() {
	puts("testadd");
	bytes(a, 16);
	unhexlify(a.begin(),
			"ff ff ff ff ff ff ff ff"
			"ff ff ff ff ff ff ff ff");
	uinta ra = FastMath32::byte2Int(a, 4);
//	_dump("a", a.begin(), 16);
//	_dump("ra", ra.begin(), 16);

	bytes(b, 20);
	unhexlify(b.begin(),
			"00 00 00 02 00 00 00 00"
			"00 00 00 00 00 00 00 00"
			"00 00 00 04");
	uinta rb = FastMath32::byte2Int(b, 5);
//	_dump("b", b.begin(), 16);
//	_dump("rb", rb.begin(), 16);

	uinta rr(5);
	int ov = FastMath32::add(rr.begin(), rb.begin(), 5, ra.begin(), 4);

	bytea r = FastMath32::int2Byte(rr, 20);

	bytes(x, 20);
	unhexlify(x.begin(),
			"00 00 00 03 00 00 00 00"
			"00 00 00 00 00 00 00 00"
			"00 00 00 03");

	return assertArrayEquals(x.begin(), r.begin(), 20) && !ov;
}


int testSub() {
	puts("testSub");
	bytes(a, 16);
	unhexlify(a.begin(), "0f 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 01");
	uinta ra = FastMath32::byte2Int(a, 4);
//	_dump("a", a.begin(), 16);
//	_dump("ra", ra.begin(), 16);

	bytes(b, 16);
	unhexlify(b.begin(), "00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 02");
	uinta rb = FastMath32::byte2Int(b, 4);
//	_dump("b", b.begin(), 16);
//	_dump("rb", rb.begin(), 16);

	uinta rr(4);
	FastMath32::sub(rr.begin(), ra.begin(), 4, rb.begin(), 4);

	bytea r = FastMath32::int2Byte(rr, 16);

	bytes(x, 16);
	unhexlify(x.begin(), "0e ff ff ff ff ff ff ff"
			"ff ff ff ff ff ff ff ff");

	return assertArrayEquals(x.begin(), r.begin(), 16);
}

int testLessThan() {
	puts("testLessThan");
	bytes(a, 16);
	unhexlify(a.begin(), "0f 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 02");
	uinta ra = FastMath32::byte2Int(a, 4);
//	_dump("a", a.begin(), 16);
//	_dump("ra", ra.begin(), 16);

	bytes(b, 16);
	unhexlify(b.begin(), "0f 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 02");
	uinta rb = FastMath32::byte2Int(b, 4);
//	_dump("b", b.begin(), 16);
//	_dump("rb", rb.begin(), 16);

	return FastMath32::isLessThan(ra.begin(), rb.begin(), 4);
}

int testXMod() {
	puts("testXMod");

	bytes(mod, 32);
	unhexlify(mod.begin(), "7F FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF"
			"FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF ED ");

	bytes(n, 64);
	unhexlify(n.begin(), "3F FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF"
			"FF FF FF FF FF FF FF FF  FF FF FF FF F6 9A 11 CD"
			"00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00  00 58 53 55 67 E0 DE 29");

	uinta imod = FastMath32::byte2Int(mod, 8);
	uinta in = FastMath32::byte2Int(n, 16);

//	_dump("n", n.begin(), n.size());
//	_dump("mod", mod.begin(), mod.size());

	FastMath32::xmod(in.begin(), imod.begin(), 16, 8);

	bytea r = FastMath32::int2Byte(in, 32);
//	_dump("r", r.begin(), 32);

	bytes(expected, 32);
	unhexlify(expected.begin(), "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00  00 58 53 54 02 BF 84 00");

	return assertArrayEquals(expected.begin(), r.begin(), 32);
}


int testMul() {
	puts("testMul");

	bytes(a, 20);
	unhexlify(a.begin(), "FFFFFFFF BBBBBBBB 55555555 01010101 00000001");

	uinta ia = FastMath32::byte2Int(a, 5);
	uinta ir(10);

	FastMath32::mul(ir.begin(), ia.begin(), ia.begin(), 5);

	bytea r = FastMath32::int2Byte(ir, 40);
//	_dump("r", r.begin(), 32);

	bytes(expected, 40);
	unhexlify(expected.begin(), "FF FF FF FF 77 77 77 76  BC DF 01 22 D3 5B E4 6D"
			"49 6B 8D B2 15 F3 D1 AF  21 77 CE 23 AE AD AC AB"
			"02 02 02 02 00 00 00 01");

	return assertArrayEquals(expected.begin(), r.begin(), 40);
}


int testSquare() {
	puts("testSquare");
	bytes(a, 20);
//	unhexlify(a.begin(), "FFFFFFFF BBBBBBBB 55555555 01010101 00000001");
	unhexlify(a.begin(), "00000000 00000000 00000001 00000001 00000001");

	uinta ia = FastMath32::byte2Int(a, 5);
	uinta ir(10);

	FastMath32::square(ir.begin(), ia.begin(), 5);

	bytea r = FastMath32::int2Byte(ir, 40);
//	_dump("r", r.begin(), 32);

	uinta mr(10);
	FastMath32::mul(mr.begin(), ia.begin(), ia.begin(), 5);
	bytea expected= FastMath32::int2Byte(mr, 40);

	return assertArrayEquals(expected.begin(), r.begin(), 40);
}

//10001
//

int testRSA() {
	puts("testRSA");
	bytes(mod, 12);
	unhexlify(mod.begin(), "00 0A 5F 4C 8F 90 9B 36 4E 03 5D C7");

	bytes(e, 3);
	unhexlify(e.begin(), "01 00 01");

	uinta en = FastMath32::byte2Int(e, 3);
	uinta modn = FastMath32::byte2Int(mod, 3);

//	_dump("en", en.begin(), 12);

//	_dump("mod", mod.begin(), 12);
//	_dump("modn", modn.begin(), 12);

	uinta rn = FastMath32::oddModPow(en, e, modn);

	bytea r = FastMath32::int2Byte(rn, 12);

	bytes(expected, 12);
	unhexlify(expected.begin(), "00 05 9F 7B 11 30 89 7C D3 FB 16 69");

	return assertArrayEquals(expected.begin(), r.begin(), 12);
}

int testBitlength() {
	puts("testBitlength");
	int bl;
	uinta t(2);
	uint32_t * x = t.begin();

	x[0] = 0x80000000;
	x[1] = 0;

	bl = FastMath32::bitLength(t.begin(), t.size());
	if (bl != 32)
		return false;

	for (int i = 0; i < 32; ++i) {
		x[1] = 1u << i;
		bl = FastMath32::bitLength(t.begin(), t.size());
		if (bl != 33 + i) {
			printf("expected %ld, got %ld\n", 33 + i, bl);
			return false;
		}
	}
	return true;
}

int testModInverse() {
	puts("testModInverse");

	bytes(bm, 32);
	unhexlify(bm.begin(), "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
	uinta im = FastMath32::byte2Int(bm, 8);

	bytes(ba, 32);
	unhexlify(ba.begin(), "4b4617c703a929bdd4a17a6b610e6696350cc9f5a3c600df6a2db6c4763014ac");
	uinta ia = FastMath32::byte2Int(ba, 8);

	uinta ir(8);
	FastMath32::modInverse(ir.begin(), ia.begin(), im.begin(), im.size());
	bytea r = FastMath32::int2Byte(ir, 32);

	bytes(expected, 32);
	unhexlify(expected.begin(), "c930c8e1cd473eb57c0cdb46ec3f0da2ba29506359c157fa22f58d08377fb464");

	return assertArrayEquals(expected.begin(), r.begin(), 32);
}

int testVerifysecp256r1() {
	puts("testVerifysecp256r1");

	bytes (sigData, 71);
	unhexlify(sigData.begin(),
			"3045"
			"0221"
			"  00E020BE 395E67EB D862DE85 096FA0BE"
			"  75ABB312 2713ED0B 127ED94E 631A27FD B4"
			"0220"
			"  5A65E6F2 2C104BB3 20A9E4B9 4D15D50D"
			"  2C564AC9 60D2AB26 0693C157 791BD829"
			);

	bytes (pubk, 66);
	unhexlify(pubk.begin(),
			"00 04 17 8D AB A8 8D 80  BF 41 F3 35 DA 91 7B 06"
			"6F A9 36 5F F0 30 42 2E  B0 5C A9 A2 7A CD 0D 96"
			"29 E1 E2 B3 1A 60 3C 5A  8B A4 3A 91 DB 38 E6 A0"
			"2F A3 73 B8 AC D3 3B 3C  D4 1E 00 BF 6A E0 19 B5"
			"5C 7B"
			);

	bytes (message, 146);
	unhexlify(message.begin(),
			"20202020 20202020 20202020 20202020"
			"20202020 20202020 20202020 20202020"
			"20202020 20202020 20202020 20202020"
			"20202020 20202020 20202020 20202020"

			"544C5320 312E332C 20736572 76657220"
			"43657274 69666963 61746556 65726966"
			"79009E8C AED65E17 A4465653 3352A591"
			"9688F61A A00D8FC0 5DDAC0F9 7165A30A"

			"B5EDE3B7 F9837341 BE73B7D7 EBFC2EC3"
			"7AEA"
			);

	SHA256 sha256;
	sha256.update(message.begin(), message.size());
	bytes (messageHash, 32);
	sha256.digest(messageHash.begin());
//	_dump("messageHash", messageHash.begin(), messageHash.size());

	bytes (expectedMessageHash, 32);
	unhexlify(expectedMessageHash.begin(),
			"FA EE 9F C4 40 C5 F4 E3  AF 3F 55 DE 8E 33 71 72"
			"6F CC 6F D5 C2 0C 1C DE  8F 7E E0 FC FB 1E 01 65"
			);
	assertArrayEquals(expectedMessageHash.begin(), messageHash.begin(), 32);

	int ok = SecpR1::verify(messageHash, sigData.begin(), sigData.size(), pubk);
	if (!ok)
		puts("verify failed");

//	int ok2 = SecpR2::verify(messageHash, sigData.begin(), sigData.size(), pubk);
//	if (!ok2)
//		puts("verify2 failed");

	return ok;
}

int main() {
	return /*testConversion()
			& testAdd()
			& testSub()
			& testLessThan() & testXMod() & testMul() & testSquare() & testRSA()
			& testBitlength()
			& testModInverse()
			& */
			testVerifysecp256r1()
			? 0 : 10;
}
