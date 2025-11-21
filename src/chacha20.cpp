/*
 * bebboget ChaCha20 / Poly1305 implementation
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
 * Purpose: Provide ChaCha20 stream cipher and Poly1305 authenticator,
 *          combined as ChaCha20-Poly1305 AEAD construction.
 *
 * Features:
 *  - ChaCha20: key setup, nonce setup, block function, stream generation
 *  - Poly1305: key setup, update, digest, modular reduction
 *  - ChaCha20Poly1305: AEAD wrapper with AAD support and authentication
 *
 * Notes:
 *  - Optimized for 32-bit word operations
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <string.h>
#include "bc.h"
#include "chacha20poly1305.h"
#include "fastmath32.h"

#undef DEBUG
#ifdef DEBUG
#endif
#include <test.h>

// ---------------- ChaCha20 ----------------

ChaCha20::~ChaCha20() {}

int ChaCha20::blockSize() const {
    return 1; // stream cipher, block size concept not used
}

void ChaCha20::decrypt(void* clearText, void const* cipherText) {
    // not used
}
void ChaCha20::encrypt(void* cipherText, void const* clearText) {
    // not used
}

int ChaCha20::setKey(void const* key, unsigned keyLen) {
    byte const* k = (byte const*) key;
    memset(state, 0, sizeof(state));
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    if (keyLen != 32)
        return false;

    for (int i = 0; i < keyLen; i += 4) {
        state[4 + (i >> 2)] = ((uint32_t) k[i + 0]) |
                              ((uint32_t) k[i + 1] << 8) |
                              ((uint32_t) k[i + 2] << 16) |
                              ((uint32_t) k[i + 3] << 24);
    }
    return true;
}

int ChaCha20::setNonce(void const* nonce, unsigned nonceLen) {
    byte const* n = (byte const*) nonce;
    if (nonceLen != 12)
        return false;

    for (int i = 0; i < nonceLen; i += 4) {
        state[13 + (i >> 2)] = ((uint32_t) n[i + 0]) |
                               ((uint32_t) n[i + 1] << 8) |
                               ((uint32_t) n[i + 2] << 16) |
                               ((uint32_t) n[i + 3] << 24);
    }
    return true;
}

#define RL(x,n) (((x)<<n) | ((x)>>(32-n)))
#define QQR(a,b,c,d) \
         a += b; d = RL(d^a,16); \
         c += d; b = RL(b^c,12); \
         a += b; d = RL(d^a,8); \
         c += d; b = RL(b^c,7);
#define QUARTERROUND(a,b,c,d) QQR(x[a],x[b],x[c],x[d])

void ChaCha20::nextBlock() {
    uint32_t x[16];
    // ChaCha20 counter wraps after 2^32 blocks (~256 GB).
    // On Amiga systems this limit is unreachable in practice.
    ++state[12]; // counter
    memcpy(x, state, 16 * sizeof(uint32_t));
    for (short i = 0; i < 10; ++i) {
        QUARTERROUND(0, 4, 8, 12);
        QUARTERROUND(1, 5, 9, 13);
        QUARTERROUND(2, 6, 10, 14);
        QUARTERROUND(3, 7, 11, 15);
        QUARTERROUND(0, 5, 10, 15);
        QUARTERROUND(1, 6, 11, 12);
        QUARTERROUND(2, 7, 8, 13);
        QUARTERROUND(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) {
        x[i] += state[i];
    }
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        uint32_t t = x[i];
        stream[j + 0] = t;
        stream[j + 1] = t >> 8;
        stream[j + 2] = t >> 16;
        stream[j + 3] = t >> 24;
    }
    pos = 0;
}

union IB {
    byte* b;
    uint32_t* i;
};

void ChaCha20::chacha(void* out, void const* in, int length) {
    int i = 0;
    IB to; to.b = (byte*) out;
    IB from; from.b = (byte*) in;
    while (i < length) {
        if (pos == 64) {
            nextBlock();
        }
        IB s; s.b = this->stream + pos;
        int count = MIN(64 - pos, length);
        length -= count;
#if 1 // optimized for 68020
        while (count > 3) {
            *to.i++ = *from.i++ ^ *s.i++;
            count -= 4;
        }
#endif
        while (count > 0) {
            *to.b++ = *from.b++ ^ *s.b++;
            --count;
        }
        pos = s.b - this->stream;
    }
}

// ---------------- Poly1305 ----------------

int Poly1305::setKey(void const* k, int klen) {
    if (klen != 32)
        return false;
    byte const* b = (byte const*) k;
#ifdef DEBUG
    _dump("poly key", k, klen);
#endif
    r[0] = 0x0fffffff & (((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24));
    b += 4;
    r[1] = 0x0ffffffc & (((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24));
    b += 4;
    r[2] = 0x0ffffffc & (((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24));
    b += 4;
    r[3] = 0x0ffffffc & (((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24));
    b += 4;
    r[4] = 0;
    s[0] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24);
    b += 4;
    s[1] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24);
    b += 4;
    s[2] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24);
    b += 4;
    s[3] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24);

    memset(a, 0, sizeof(a));
    return true;
}

#ifdef __mc68020__
extern "C" {
extern void addmodmul(uint32_t* a, uint32_t const* n, uint32_t const* r);
};
#else

#if __AMIGA__
extern "C" void mod5(uint32_t* t);
#else
static inline void mod5(uint32_t* t) {
    uint32_t o = 0;
    for (int i = 5; i >= 0; --i) {
        uint32_t x = t[i + 4];
        t[i + 4] = 0;
        uint32_t add = x >> 2;
        add += o;
        o = x << 30;
        uint64_t c = add;
        c <<= 2;
        c += add;
        for (int j = i; c; ++j) {
            c += t[j];
            t[j] = c;
            c >>= 32;
        }
    }
    t[4] += o >> 30;
    if (t[4] > 3 || (t[4] == 3 && t[3] == 0xffffffff && t[2] == 0xffffffff && t[1] == 0xffffffff && t[0] > 0xfffffffb)) {
        int64_t c = t[0]; c -= 0xfffffffb; t[0] = c;
        c >>= 32; c += t[1]; c -= 0xffffffff; t[1] = c;
        c >>= 32; c += t[2]; c -= 0xffffffff; t[2] = c;
        c >>= 32; c += t[3]; c -= 0xffffffff; t[3] = c;
        c >>= 32; c += t[4]; c -= 3; t[4] = c;
    }
}
#endif

#define addmodmul caddmodmul

void caddmodmul(uint32_t* a, uint32_t const* n, uint32_t const* r) {
    static uint32_t const p[5] = { 0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff, 3 };
    uint32_t t[5];

    uint64_t c = a[0]; c += n[0]; t[0] = c;
    c >>= 32; c += a[1]; c += n[1]; t[1] = c;
    c >>= 32; c += a[2]; c += n[2]; t[2] = c;
    c >>= 32; c += a[3]; c += n[3]; t[3] = c;
    c >>= 32; c += a[4]; c += n[4]; t[4] = c;

    FastMath32::mul(a, t, r, 5);
    mod5(a);
}
#endif

void Poly1305::update(void const* d, int len) {
    byte const* b = (byte const*) d;
#ifdef DEBUG
    _dump("poly update", d, len);
#endif
    while (len > 16) {
        uint32_t n[5] = {
            ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24),
            ((uint32_t) b[4]) | ((uint32_t) b[5] << 8) | ((uint32_t) b[6] << 16) | ((uint32_t) b[7] << 24),
            ((uint32_t) b[8]) | ((uint32_t) b[9] << 8) | ((uint32_t) b[10] << 16) | ((uint32_t) b[11] << 24),
            ((uint32_t) b[12]) | ((uint32_t) b[13] << 8) | ((uint32_t) b[14] << 16) | ((uint32_t) b[15] << 24),
            1
        };
        addmodmul(a, n, r);
        len -= 16;
        b += 16;
    }

    while (len > 0) {
        uint32_t n[5];
        for (int i = 0; i < 4; ++i) {
            if (len >= 4) {
                n[i] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24);
            } else if (len == 3) {
                n[i] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | 0x1000000;
            } else if (len == 2) {
                n[i] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | 0x10000;
            } else if (len == 1) {
                n[i] = ((uint32_t) b[0]) | 0x100;
            } else {
                n[i] = len == 0 ? 1 : 0;
            }
            b += 4;
            len -= 4;
        }
        n[4] = (len >= 0) ? 1 : 0;
        addmodmul(a, n, r);
        len -= 16;
    }
}

void Poly1305::digest(void* to) {
    FastMath32::add(a, a, 5, s, 4);
    byte* p = (byte*) to;
    for (int i = 0, j = 0; i < 4; ++i, j += 4) {
        uint32_t t = a[i];
        p[j + 0] = t;
        p[j + 1] = t >> 8;
        p[j + 2] = t >> 16;
        p[j + 3] = t >> 24;
    }
}

// ---------------- ChaCha20-Poly1305 AEAD ----------------

ChaCha20Poly1305::~ChaCha20Poly1305() {}

int ChaCha20Poly1305::setKey(const void* key, unsigned keylen) {
    return cc.setKey(key, keylen);
}

void ChaCha20Poly1305::init(const void* nonce, int nonceLength) {
    cc.setNonce(nonce, nonceLength);
    cc.zeroCounter();
    cc.nextBlock();
    poly.setKey(cc.getStream(), 32);
    cc.pos = 64;
    aadLen = 0;
}

void ChaCha20Poly1305::decrypt(void*, void const*) {
    // not used
}

void ChaCha20Poly1305::encrypt(void*, void const*) {
    // not used
}

int ChaCha20Poly1305::blockSize() const {
    return 1;
}

int ChaCha20Poly1305::isAAD() const {
    return true;
}

void ChaCha20Poly1305::updateHash(void const* d, int sz) {
    byte aad[16];
    memcpy(aad, d, sz);
    memset(aad + sz, 0, 16 - sz);
    poly.update(aad, 16);
    aadLen = sz;
}

void ChaCha20Poly1305::calcHash(void* to) {
    poly.digest(to);
}

void ChaCha20Poly1305::polly(void const* cipher, int len) {
    int rest = (len & 15);
    int end = len - rest;
    if (end)
        poly.update(cipher, end);

    if (rest) {
        byte b0[16];
        int i = 0;
        byte const* c = (byte const*) cipher;
        for (; i < rest; ++i) {
            b0[i] = c[end + i];
        }
        for (; i < 16; ++i) {
            b0[i] = 0;
        }
        poly.update(b0, 16);
    }

    // RFC 7539 requires 64-bit little-endian lengths of AAD and ciphertext.
    // In SSL/TLS usage here, aadLen is always < 128, so we only store it in one byte.
    byte b1[16] = { aadLen, 0, 0, 0, 0, 0, 0, 0 };
    int l = len;
    for (int i = 8; i < 16; ++i) {
        b1[i] = l;
        l >>= 8;
    }
    poly.update(b1, 16);
}

void ChaCha20Poly1305::encrypt(void* cipher, void const* clear, int len) {
    cc.chacha(cipher, clear, len);
    polly(cipher, len);
}

void ChaCha20Poly1305::decrypt(void* clear, void const* cipher, int len) {
    polly(cipher, len);
    cc.chacha(clear, cipher, len);
}

/*
 * End of ChaCha20 / Poly1305 implementation
 */
