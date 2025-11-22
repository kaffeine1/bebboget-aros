/*
 * bebboget RC4 stream cipher interface
 * Copyright (C) 1998, 2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide RC4 stream cipher interface derived from BlockCipher.
 *
 * Features:
 *  - setKey() to initialize RC4 key schedule
 *  - encrypt() and decrypt() stream operations
 *  - blockSize() reports cipher block size (RC4 is byte-oriented)
 *  - CBC-style wrappers provided for compatibility, though RC4 is a stream cipher
 *
 * Notes:
 *  - RC4 is considered cryptographically broken; use only for legacy
 *    compatibility, not for secure applications.
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __RC4_H__
#define __RC4_H__

#include <bc.h>
#include <bytearray.h>

class RC4 : public BlockCipher {
	uint8_t key[258];  ///< RC4 key schedule buffer

public:
    /// Construct RC4 cipher
    inline RC4() {}

    /// Virtual destructor
    virtual ~RC4();

    /// Decrypt stream
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Encrypt stream
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Set RC4 key schedule
    virtual int setKey(void const* key, unsigned keylen);

    /// Return block size (RC4 is byte-oriented, typically 1)
    virtual int blockSize() const;

    /// Decrypt using CBC-style wrapper
    virtual void decryptCBC(void* iv, void* to, void const* from, unsigned long len);

    /// Encrypt using CBC-style wrapper
    virtual void encryptCBC(void* iv, void* to, void const* from, unsigned long len);
};

#endif // __RC4_H__
