/*
 * bebboget - SSL for the Amiga
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
 * Project: SSL for the Amiga
 * Purpose: Provide modern SSL/TLS cryptographic primitives and protocol
 *          support on classic Amiga systems.
 *
 * Features:
 *  - ASN1 support functions
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Optimized for Motorola 68000/68020 CPUs with inline assembly support.
 *
 * Author's intent:
 *  Ensure Amiga developers have access to secure, maintainable,
 *  and GPL-compliant cryptographic building blocks.
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include "asn1.h"

#undef DEBUG
#ifdef DEBUG
#include <test.h>
#else
#define _dump(a,b,c)
#endif

#ifdef __AMIGA__
#include <amistdio.h>
#else
#include <stdio.h>
#endif

/** ASN.1 path to the public key inside a x.509 certificate. */
uint8_t Asn1::PK_PATH[] = { 0x90, 0x90, 0x10, 0x10, 0x10, 0x10, 0x90, 0x83, 0 };

/** ASN.1 path to the public modulo inside the public key. */
uint8_t Asn1::MODULO_PATH[] = { 0x90, 0x82, 0 };

/** ASN.1 path to the public exponent inside the public key. */
uint8_t Asn1::EXPONENT_PATH[] = { 0x90, 0x02, 0x82, 0 };

bytea Asn1::getSeq(bytez const &b, uint8_t const *s, int off) {
	if (b.size() == 0 || s == 0 || *s == 0)
		return bytea();

#ifdef DEBUG
_dump("asn1", b.begin(), b.size());
#endif

	int typ, len = 0, end = b.size();
	for (int i = 0; s[i];) {

		if (off < 0 || off + 2 >= b.size())
			return 0;

		int start = off;
		typ = b[off++] & 0x1f;
		len = (signed char) b[off++];
		if (len < 0) {
			int n = len & 0x7f;
			len = 0;
			while (n-- > 0) {
				len = (len << 8) | (b[off++] & 0xff);
			}
			if (len == 0) // no length given -> use the rest!
				len = end - off;
		}
#ifdef DEBUG
	printf("off=%lx, type=%ld, len=%ld\n", off, typ, len);
#endif
		if (s[i] == typ) {
			++i;
			if (!s[i]) {
				len += off - start;
				off = start;
			}
		} else if ((0x7f & s[i]) == typ) {
			++i;
			end = off + len;
			continue;
		}
		if (s[i])
			off += len;
	}
	bytea r(len);
	memcpy(r.begin(), b.begin() + off, len);
	return r;
}

/**
 * Creates a new byte array containing an ASN.1 element.
 *
 * @param b
 *            the bytes of the new ASN.1 element.
 * @param typ
 *            the kind of the new ASN.1 element.
 * @return a new allocated byte array containing an ASN.1 element.
 */
bytea Asn1::makeASN1(bytez const &b, int typ) {
	unsigned n = 2;
	int len = b.size();
	if (typ == 3)
		++len;
	if (len > 0x7f) {
		for (unsigned i = b.size(); i > 0; i >>= 8)
			++n;
	}
	bytea r(n + len);
	r[0] = (uint8_t) typ;
	if (len > 0x7f) {
		r[1] = (uint8_t) (0x80 + n - 2);
		unsigned i = n;
		while (i > 2) {
			r[--i] = (uint8_t) len;
			len = (unsigned) len >> 8;
		}
	} else
		r[1] = (uint8_t) len;
	if (typ == 3)
		r[n++] = 0;
	memcpy(r.begin() + n, b.begin(), b.size());
#ifdef DEBUG
	_dump("makeASN1", r.begin(), r.size());
#endif
	return r;
}

bytea Asn1::addTo(bytez const &seqOrSet, bytez const &dataToAdd) {
	int off = 0;
	int typ = seqOrSet[off++];
	int len = (signed char)seqOrSet[off++];
	if (len < 0) {
		int n = len & 0x7f;
		len = 0;
		while (n-- > 0) {
			len = (len << 8) | (seqOrSet[off++] & 0xff);
		}
	}
	bytea r(len + dataToAdd.size());
	memcpy(r.begin(), seqOrSet.begin() + off, len);
//		System.arraycopy(seqOrSet, off, r, 0, len);
	memcpy(r.begin() + r.size() - dataToAdd.size(), dataToAdd.begin(), dataToAdd.size());
//		System.arraycopy(dataToAdd, 0, r, r.length - dataToAdd.length, dataToAdd.length);
	return makeASN1(r, typ);
}

bytea Asn1::encodeOIDInteger(unsigned n) {
	int j = 0;
	for (unsigned k = n; k != 0; k >>= 7) {
		++j;
	}
	if (j == 0)
		j = 1;

	bytea bb(j);
	uint8_t *b = bb.begin();
	for (int k = 0; k < j; ++k) {
		b[k] = (uint8_t) ((0x7f & (n >> (j - k - 1) * 7)) | (k + 1 < j ? 0x80 : 0));
	}
	return bb;
}

bytea Asn1::string2Oid(char const *ss) {
	char * s0 = strdup(ss);
	char * s = s0;
	bytea bb(strlen(s));
	uint8_t *b = bb.begin();
//	puts(s);

	char *q = s;
	while (*q && *q != '.')
		++q;

	if (*q) {
		*q = 0;
		int z = atoi(s) * 40;

//		puts(s);
//		printf("z=%ld\n", z);

		s = ++q;
		while (*q && *q != '.')
			++q;

		if (*q) {
			*q = 0;
			z += atoi(s);
//			puts(s);
//			printf("z=%ld\n", z);
			*b++ = z;

			int run = true;
			while (run) {
				s = ++q;
				while (*q && *q != '.')
					++q;

				run = *q;
				*q = 0;
				int n = atoi(s);
//				puts(s);
//				printf("n=%ld\n", n);
				bytea d = encodeOIDInteger(n);
				memcpy(b, d.begin(), d.size());
				b += d.size();
			}
		}
	}
	free(s0);
	bb.setSize(b - bb.begin());
	return bb;
}


bytea Asn1::getData(bytez const & ba, int off) {
	uint8_t const * b = ba.begin();
	// int start = off;
	// int typ = b[off++];
	++off;
	int len = b[off++];
	if (len == -128) {
		len = ba.size() - off;
	} else if (len < 0) {
		int n = len & 0x7f;
		len = 0;
		while (n-- > 0) {
			len = (len << 8) | (b[off++] & 0xff);
		}
	}
	if (len + off > ba.size())
		len = ba.size() - off;
	bytea r(len);
	memcpy(r.begin(), b + off, len);
	return r;
}
