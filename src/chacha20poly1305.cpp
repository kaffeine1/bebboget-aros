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
	uint8_t aad[16];
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
    	uint8_t b0[16];
        int i = 0;
        uint8_t const* c = (uint8_t const*) cipher;
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
    uint8_t b1[16] = { aadLen, 0, 0, 0, 0, 0, 0, 0 };
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
