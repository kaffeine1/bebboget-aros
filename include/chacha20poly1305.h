/*
 * bebboget ChaCha20-Poly1305 AEAD interface
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
 * Purpose: Provide AEAD (Authenticated Encryption with Associated Data)
 *          using ChaCha20 stream cipher and Poly1305 authenticator.
 *
 * Features:
 *  - ChaCha20 stream cipher implementation
 *  - Poly1305 message authentication code
 *  - Combined ChaCha20-Poly1305 AEAD construction
 *  - Support for nonce initialization, AAD processing, and tag calculation
 *
 * Notes:
 *  - ChaCha20 provides encryption/decryption of arbitrary-length streams
 *  - Poly1305 provides authentication over ciphertext and AAD
 *  - ChaCha20Poly1305 integrates both for AEAD usage
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __CHACHA20POLY1305__H__
#define __CHACHA20POLY1305__H__

#include "bc.h"

/**
 * @class ChaCha20
 * @brief ChaCha20 stream cipher implementation.
 *
 * Provides encryption and decryption of data streams using
 * the ChaCha20 algorithm. Supports nonce setup and block
 * generation for stream output.
 */
class ChaCha20 : public BlockCipher {
    friend class ChaCha20Poly1305;
    uint32_t state[16]; ///< Internal state
    byte stream[64];    ///< Current keystream block
    int pos;            ///< Position within stream
public:
    /// Constructor initializes position to end of stream
    ChaCha20() : pos(64) {}
    virtual ~ChaCha20();

    /// Decrypt data using ChaCha20
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Encrypt data using ChaCha20
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Set key material
    virtual int setKey(void const* key, unsigned keylen);

    /// Return block size (64 bytes for ChaCha20)
    virtual int blockSize() const;

    /// Encrypt/decrypt arbitrary-length stream
    void chacha(void* cipherText, void const* clearText, int length);

    /// Set nonce for stream cipher
    int setNonce(void const* nonce, unsigned nonceLen);

    /// Generate next keystream block
    void nextBlock();

    /// Access current keystream
    inline byte const* getStream() const { return stream; }

    /// Reset counter to initial value
    void zeroCounter() { state[12] = 0xffffffff; }
};

/**
 * @class Poly1305
 * @brief Poly1305 message authentication code.
 *
 * Provides authentication over ciphertext and AAD
 * using a one-time key derived from ChaCha20.
 */
class Poly1305 {
    uint32_t r[5]; ///< Key parameter r
    uint32_t s[4]; ///< Key parameter s
    uint32_t a[10];///< Accumulator
public:
    /// Set Poly1305 key
    int setKey(void const* k, int klen);

    /// Update MAC with data
    void update(void const* d, int len);

    /// Finalize and produce digest
    void digest(void* to);
};

/**
 * @class ChaCha20Poly1305
 * @brief AEAD construction combining ChaCha20 and Poly1305.
 *
 * Provides authenticated encryption with associated data (AEAD)
 * using ChaCha20 for encryption and Poly1305 for authentication.
 */
class ChaCha20Poly1305 : public AeadBlockCipher {
    ChaCha20 cc;   ///< ChaCha20 cipher
    Poly1305 poly; ///< Poly1305 authenticator
    byte aadLen;   ///< Length of AAD processed

    /// Internal helper for Poly1305 update
    void polly(void const* cipher, int len);
public:
    ChaCha20Poly1305() : aadLen(0) {}
    virtual ~ChaCha20Poly1305();

    /// Indicates AEAD support
    virtual int isAAD() const;

    /// Return block size (64 bytes for ChaCha20)
    virtual int blockSize() const;

    /// Encrypt with AEAD
    virtual void encrypt(void* cipherText, void const* clearText, int length);

    /// Decrypt with AEAD
    virtual void decrypt(void* clearText, void const* cipherText, int length);

    /// Initialize with nonce
    virtual void init(void const* nonce, int nonceLength);

    /// Update authentication hash with AAD
    virtual void updateHash(void const* aad, int len);

    /// Calculate authentication tag
    virtual void calcHash(void* to);

    /// Encrypt single block
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Decrypt single block
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Set key material
    int setKey(void const* key, unsigned keylen);
};

#endif // __CHACHA20POLY1305__H__
