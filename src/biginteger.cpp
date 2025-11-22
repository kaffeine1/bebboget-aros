/*
 * bebboget BigInteger implementation
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
 * Purpose: Provide arbitrary-precision integer arithmetic for cryptographic
 *          routines (modular inverse, multiplication, squaring, shifting).
 *          Provide optimized modular reduction routines for elliptic
 *          curve primes (Secp256r1 and Secp384r1), plus general mod
 *          operations for BigInteger.
 *
 * Features:
 *  - Memory pool for efficient allocation of temporary buffers
 *  - Constructors for various input formats (uint, byte array, other BigInteger)
 *  - Arithmetic operations: add, subtract, multiply, square
 *  - Bitwise shifts and modular inverse
 *  - fastSecp256Mod(): reduction modulo P-256 prime
 *  - fastSecp384Mod(): reduction modulo P-384 prime
 *  - modSecP(): wrapper selecting reduction based on modulus size
 *  - mod(): generic modular reduction using xmod
 *  - equals(), toByteArray(), toString() helpers
 *
 * Notes:
 *  - Uses FastMath32 routines for low-level arithmetic
 *  - Optimized reduction avoids division, relying on carry propagation
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

/*
 * biginteger.cpp
 *
 *  Created on: Apr 8, 2025
 *      Author: stefan
 */
#include <stdlib.h>
#include <string.h>
#include <biginteger.h>
#include <unhexlify.h>

#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

#include <test.h>

/// Memory pool for BigInteger temporary buffers
class MemPool {
    union E {
        E* next;
        uint32_t first;
    };
    E* free;
public:
    int size;

    MemPool() : free(), size() {}
    /// Allocate a block from the pool
    uint32_t* get() {
        if (!free) {
            init(16, 2*18); // 521 bits -> 18 words
            if (!free) {
                puts("MemPool: no free block");
                exit(20);
            }
        }
        E* t = free;
        free = t->next;
        return &t->first;
    }
    /// Return a block to the pool
    void put(uint32_t* p) {
        E* e = (E*)p;
        e->next = free;
        free = e;
    }
    /// Initialize pool with given count and size
    void init(int count, int size) {
        size += 2;
        this->size = size;
        uint32_t* x = (uint32_t*)malloc(count * size * sizeof(uint32_t));
        for (int i = 0; i < count; ++i) {
            put(x);
            x += size;
        }
    }
};

MemPool M;

/// Construct BigInteger from unsigned int
BigInteger::BigInteger(unsigned int ui)
: signum(1), usedLen(1), n(new uint32_t[20]) {
    memset(n + 1, 0, sizeof(uint32_t) * 19);
    n[0] = ui;
}

/// Construct BigInteger from byte array
BigInteger::BigInteger(short signum_, uint8_t const* b, int len)
: signum(signum_), n(M.get()) {
    bytez ba(b, len);
    uinta i = FastMath32::byte2Int(ba, (ba.size() + 3) / 4);
    memcpy(n, i.begin(), i.size() * sizeof(uint32_t));
    shrink(i.size());
}

/// Construct BigInteger from uinta
BigInteger::BigInteger(short signum_, uinta const& no)
: signum(signum_), n(M.get()) {
    memcpy(n, no.begin(), no.size() * sizeof(uint32_t));
    shrink(no.size());
}

/// Destructor returns memory to pool
BigInteger::~BigInteger() {
    if (n) M.put(n);
}

/// Move constructor
BigInteger::BigInteger(BigInteger&& o)
: signum(o.signum), usedLen(o.usedLen), n(o.n) {
    o.n = 0;
}

/// Copy assignment
BigInteger& BigInteger::operator=(BigInteger const& o) {
    signum = o.signum;
    usedLen = o.usedLen;
    memcpy(n, o.n, usedLen * sizeof(uint32_t));
    return *this;
}

/// Move assignment
BigInteger& BigInteger::operator=(BigInteger&& o) {
    signum = o.signum;
    usedLen = o.usedLen;
    M.put(n);
    n = o.n;
    o.n = 0;
    return *this;
}

/// Copy constructor
BigInteger::BigInteger(BigInteger const& o)
: signum(o.signum), usedLen(o.usedLen), n(M.get()) {
    memcpy(n, o.n, usedLen * sizeof(uint32_t));
}

/// Construct from raw buffer
BigInteger::BigInteger(short signum_, uint32_t* no, int usedLen)
: signum(signum_), n(no) {
    shrink(usedLen);
}

/// Shrink length by removing leading zeros
void BigInteger::shrink(int c) {
    usedLen = c;
    uint32_t* p = n;
    while (usedLen > 1 && p[usedLen - 1] == 0) {
        --usedLen;
    }
}

/// Modular inverse
BigInteger BigInteger::modInverse(BigInteger const& modulo) const {
    uint32_t* r = M.get();
    FastMath32::modInverse(r, n, modulo.n, modulo.usedLen);
    BigInteger b = BigInteger(signum, r, modulo.usedLen);
    return b;
}

/// Multiplication
BigInteger BigInteger::multiply(BigInteger const& factor) const {
    if (usedLen > factor.usedLen)
        return factor.multiply(*this);

    for (int i = usedLen; i < factor.usedLen; ++i) {
        n[i] = 0;
    }

    uint32_t* r = M.get();
    FastMath32::mul(r, n, factor.n, factor.usedLen);
    return BigInteger(signum * factor.signum, r, factor.usedLen * 2);
}

/// Square
BigInteger BigInteger::square() const {
    uint32_t* r = M.get();
    FastMath32::square(r, n, usedLen);
    return BigInteger(1, r, usedLen * 2);
}

/// Addition
BigInteger BigInteger::add(BigInteger const& b, short overrideBSig) const {
    if (!overrideBSig) overrideBSig = b.signum;
    if (signum != overrideBSig) {
        if (signum == 1) return subtract(b, 1);
        return b.subtract(*this, 1);
    }

    uint32_t* r = M.get();
    int l = MAX(usedLen, b.usedLen);
    if (FastMath32::add(r, n, usedLen, b.n, b.usedLen)) {
        r[l++] = 1;
    }
    return BigInteger(signum, r, l);
}

/// Subtraction
BigInteger BigInteger::subtract(BigInteger const& s, short overrideBSig) const {
    if (!overrideBSig) overrideBSig = s.signum;
    if (signum != overrideBSig) return add(s, signum);

    uint32_t* r = M.get();
    int len = MAX(usedLen, s.usedLen);
    if (FastMath32::sub(r, n, usedLen, s.n, s.usedLen)) {
        // negate on underflow
        int index = 0;
        for (; index < len; ++index) {
            if (r[index] != 0) break;
        }
        r[index] = -r[index];
        for (++index; index < len; ++index) {
            r[index] = ~r[index];
        }
        return BigInteger(-signum, r, len);
    }
    return BigInteger(signum, r, len);
}

/// Shift left
BigInteger BigInteger::shiftLeft(int shift) const {
    if (shift == 0) return *this;
    if (shift < 0) return shiftRight(-shift);

    int len = usedLen + 1;
    uint32_t* r = M.get();
    n[usedLen] = 0;
    FastMath32::shiftLeft(r, n, len, shift);
    return BigInteger(signum, r, len);
}

/// Shift right
BigInteger BigInteger::shiftRight(int shift) const {
    if (shift == 0) return *this;
    if (shift < 0) return shiftLeft(-shift);

    uint32_t* r = M.get();
    FastMath32::shiftRight(r, n, usedLen, shift);
    return BigInteger(signum, r, usedLen);
}

/// Optimized reduction modulo Secp256r1 prime
/// Input: c[0..15] (512-bit intermediate product)
/// Output: t[0..7] (256-bit reduced value)
/// Method: Fold high words back into low words using the special form of P-256
void fastSecp256Mod(uint32_t* c, uint32_t* t, uint32_t* P) {
    int64_t carry = 0;

    // Each step accumulates contributions from high words (c[8..15])
    // into low words (c[0..7]) with signed adjustments.
    // This exploits the pseudo-Mersenne prime structure of P-256.

    // i = 0 reduction
    carry += (int64_t)c[0] + c[8] + c[9] - c[11] - c[12] - c[13] - c[14];
    t[0] = carry; carry >>= 32;

    // i = 1 reduction
    carry += (int64_t)c[1] + c[9] + c[10] - c[12] - c[13] - c[14] - c[15];
    t[1] = carry; carry >>= 32;

    // i = 2 reduction
    carry += (int64_t)c[2] + c[10] + c[11] - c[13] - c[14] - c[15];
    t[2] = carry; carry >>= 32;

    // i = 3 reduction
    carry += (int64_t)c[3] + c[11] + c[11] + c[12] + c[12] + c[13] - c[15] - c[8] - c[9];
    t[3] = carry; carry >>= 32;

    // i = 4 reduction
    carry += (int64_t)c[4] + c[12] + c[12] + c[13] + c[13] + c[14] - c[9] - c[10];
    t[4] = carry; carry >>= 32;

    // i = 5 reduction
    carry += (int64_t)c[5] + c[13] + c[13] + c[14] + c[14] + c[15] - c[10] - c[11];
    t[5] = carry; carry >>= 32;

    // i = 6 reduction
    carry += (int64_t)c[6] + c[14] + c[14] + c[15] + c[15] + c[14] + c[13] - c[8] - c[9];
    t[6] = carry; carry >>= 32;

    // i = 7 reduction
    carry += (int64_t)c[7] + c[15] + c[15] + c[15] + c[8] - c[10] - c[11] - c[12] - c[13];
    t[7] = carry; carry >>= 32;

    // Final correction loop: ensure result is within [0, P)
    int f = carry;
    if (f < 0) {
        while (f < 0) {
            if (FastMath32::add(t, t, 8, P, 8)) ++f;
        }
    } else {
        while (f > 0) {
            if (FastMath32::sub(t, t, P, 8)) --f;
        }
        if (FastMath32::isLessThan(P, t, 8))
            FastMath32::sub(t, t, P, 8);
    }
}

/// Optimized reduction modulo Secp384r1 prime
/// Input: c[0..23] (768-bit intermediate product)
/// Output: t[0..11] (384-bit reduced value)
/// Method: Fold high words back into low words using the special form of P-384
void fastSecp384Mod(uint32_t* c, uint32_t* t, uint32_t* P) {
    int64_t carry = 0;

    // Each step accumulates contributions from high words (c[12..23])
    // into low words (c[0..11]) with signed adjustments.
    // This exploits the pseudo-Mersenne prime structure of P-384.

    carry += (int64_t)c[0] + c[12] + c[21] + c[20] - c[23];
    t[0] = carry; carry >>= 32;

    carry += (int64_t)c[1] + c[13] + c[22] + c[23] - c[12] - c[20];
    t[1] = carry; carry >>= 32;

    carry += (int64_t)c[2] + c[14] + c[23] - c[13] - c[21];
    t[2] = carry; carry >>= 32;

    carry += (int64_t)c[3] + c[15] + c[12] + c[20] + c[21] - c[14] - c[22] - c[23];
    t[3] = carry; carry >>= 32;

    carry += (int64_t)c[4] + c[21] + c[21] + c[16] + c[13] + c[12] + c[22] - c[15] - c[23] - c[23];
    t[4] = carry; carry >>= 32;

    carry += (int64_t)c[5] + c[22] + c[22] + c[17] + c[14] + c[13] + c[23] - c[16];
    t[5] = carry; carry >>= 32;

    carry += (int64_t)c[6] + c[23] + c[23] + c[18] + c[15] + c[14] - c[17];
    t[6] = carry; carry >>= 32;

    carry += (int64_t)c[7] + c[19] + c[16] + c[15] - c[18];
    t[7] = carry; carry >>= 32;

    carry += (int64_t)c[8] + c[20] + c[17] + c[16] - c[19];
    t[8] = carry; carry >>= 32;

    carry += (int64_t)c[9] + c[21] + c[18] + c[17] - c[20];
    t[9] = carry; carry >>= 32;

    carry += (int64_t)c[10] + c[22] + c[19] + c[18] - c[21];
    t[10] = carry; carry >>= 32;

    carry += (int64_t)c[11] + c[23] + c[20] + c[19] - c[22];
    t[11] = carry; carry >>= 32;

    // Final correction loop: ensure result is within [0, P)
    int f = carry;
    if (f < 0) {
        while (f < 0) {
            if (FastMath32::add(t, t, 12, P, 12)) ++f;
        }
    } else {
        while (f > 0) {
            if (FastMath32::sub(t, t, P, 12)) --f;
        }
        if (FastMath32::isLessThan(P, t, 12))
            FastMath32::sub(t, t, P, 12);
    }
}

/// Modular reduction specialized for Secp256r1 / Secp384r1
BigInteger BigInteger::modSecP(BigInteger const& P) const {
    uint32_t* t = M.get();
    memcpy(t, n, usedLen * sizeof(uint32_t));

    if (P.usedLen == 8) { // Secp256r1
        if (usedLen > 8) {
            if (usedLen == 17) {
                int f = n[16]; n[16] = 0;
                while (f > 0) {
                    if (FastMath32::sub(n + 8, n + 8, P.n, 8)) --f;
                }
            } else {
                for (int i = usedLen; i < 16; ++i) n[i] = 0;
            }
            fastSecp256Mod(n, t, P.n);
        } else {
            if (usedLen < 8) {
                for (int i = usedLen; i < 8; ++i) n[i] = 0;
            } else if (FastMath32::isLessThan(P.n, t, 8)) {
                FastMath32::sub(t, t, P.n, 8);
            }
        }
    } else { // Secp384r1
        if (usedLen > 12) {
            if (usedLen == 25) {
                int f = n[24]; n[24] = 0;
                while (f > 0) {
                    if (FastMath32::sub(n + 12, n + 12, P.n, 12)) --f;
                }
            } else {
                for (int i = usedLen; i < 24; ++i) n[i] = 0;
            }
            fastSecp384Mod(n, t, P.n);
        } else {
            if (usedLen < 12) {
                for (int i = usedLen; i < 12; ++i) n[i] = 0;
            } else if (FastMath32::isLessThan(P.n, t, 12)) {
                FastMath32::sub(t, t, P.n, 12);
            }
        }
    }

    if (signum == -1) {
        FastMath32::sub(t, P.n, t, P.usedLen);
    }

    return BigInteger(1, t, MIN(usedLen, P.usedLen));
}

/// Generic modular reduction
BigInteger BigInteger::mod(BigInteger const& m) const {
    if (usedLen < m.usedLen)
        return BigInteger(*this);

    int l2 = usedLen + 2;
    uint32_t* r = M.get();
    r[usedLen] = 0;
    memcpy(r, n, usedLen * sizeof(uint32_t));

    uinta t1(l2);
    t1.begin()[usedLen] = 0;

    uinta t2(l2);
    t2.begin()[usedLen] = 0;
    t2.begin()[usedLen + 1] = 0;

    FastMath32::xmod(r, m.n, usedLen + 1, m.usedLen);

    if (signum == -1)
        FastMath32::sub(r, m.n, r, m.usedLen);

    return BigInteger(1, r, m.usedLen);
}

/// Equality check
int BigInteger::equals(BigInteger const& b) const {
    if (usedLen != b.usedLen)
        return false;
    uint32_t const* x = n;
    uint32_t const* y = b.n;
    for (int i = 0; i < usedLen; ++i) {
        if (x[i] != y[i])
            return false;
    }
    return true;
}

/// Convert to byte array
bytea BigInteger::toByteArray() const {
    return FastMath32::int2Byte(n, usedLen, usedLen * 4);
}

/// Convert to hex string
char* BigInteger::toString() const {
    bytea b = toByteArray();
    char* p = hexlify(b.begin(), b.size());
    while (*p && *p == '0')
        ++p;
    if (!*p) --p;
    return p;
}
