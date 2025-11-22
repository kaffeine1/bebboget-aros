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
#include "chacha20.h"
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

    state[12] = 0; state[13] = 0;
    state[14] = 0; state[15] = 0;

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

    x[0]  = state[0];  x[1]  = state[1];
    x[2]  = state[2];  x[3]  = state[3];
    x[4]  = state[4];  x[5]  = state[5];
    x[6]  = state[6];  x[7]  = state[7];
    x[8]  = state[8];  x[9]  = state[9];
    x[10] = state[10]; x[11] = state[11];
    x[12] = state[12]; x[13] = state[13];
    x[14] = state[14]; x[15] = state[15];

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

