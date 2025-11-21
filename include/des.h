/*
 * bebboget DES block cipher interface
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
 * Purpose: Provide DES block cipher interface derived from BlockCipher.
 *
 * Features:
 *  - setKey() to configure DES key schedule
 *  - encrypt() and decrypt() block operations
 *  - blockSize() reports cipher block size
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __DES_H__
#define __DES_H__

#include <bc.h>
#include <bytearray.h>

class DES : public BlockCipher {
    int keyLen;
    uint32_t keyData[32];

    /// Internal DES round function
    void des(void* clearText, void const* cipherText, int n);

public:
    /// Construct DES cipher with optional key length (default 8 bytes)
    explicit DES(int kl = 8);

    /// Virtual destructor
    virtual ~DES();

    /// Copy constructor and assignment are fine
    DES(const DES&) = default;
    DES& operator=(const DES&) = default;

    /// Decrypt a block
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Encrypt a block
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Set key schedule
    virtual int setKey(void const* key, unsigned keylen);

    /// Return block size in bytes
    virtual int blockSize() const;
};

#endif // __DES_H__
