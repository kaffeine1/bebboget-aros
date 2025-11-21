/*
 * bebboget Triple DES (DES3) block cipher interface
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
 * Purpose: Provide Triple DES (3DES) block cipher interface derived from DES.
 *
 * Features:
 *  - setKey() to configure three DES keys
 *  - encrypt() and decrypt() using EDE (Encrypt-Decrypt-Encrypt) sequence
 *  - blockSize() inherited from DES
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __DES3_H__
#define __DES3_H__

#include <des.h>

class DES3 : public DES {
    DES desB;  ///< second DES instance
    DES desC;  ///< third DES instance

public:
    /// Construct Triple DES cipher with default DES base
    inline DES3() : DES(), desB(), desC() {}

    /// Virtual destructor
    virtual ~DES3();

    /// Decrypt a block using 3DES sequence
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Encrypt a block using 3DES sequence
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Set three keys for 3DES
    virtual int setKey(void const* key, unsigned keylen);
};

#endif // __DES3_H__
