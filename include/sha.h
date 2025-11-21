/*
 * bebboget SHA message digest interface (SHA-1 style core)
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
 * Purpose: Provide SHA message digest implementation derived from
 *          MessageDigest base class.
 *
 * Features:
 *  - Implements SHA compression function (transform)
 *  - Maintains internal state words
 *  - Provides len(), clone(), reset(), and digest extraction
 *
 * Notes:
 *  - This class models SHA-1 style operations (five state words, 80 rounds)
 *  - Inline round macros (R00-R04) implement core step functions
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SHA_H__
#define __SHA_H__

#include <md.h>

class SHA : public MessageDigest { // @suppress("Class has a virtual method and non-virtual destructor")
    unsigned long state0, state1, state2, state3, state4;  ///< SHA state words
    unsigned long t0, t1, t2, t3, t4, add;                 ///< working registers
    unsigned long block[20];                               ///< message block buffer

public:
    /// Construct SHA digest
    SHA();

    /// Return digest length in bytes
    virtual unsigned len() const;

    /// Clone this digest instance
    virtual MessageDigest* clone() const;

protected:
    /// SHA compression function
    void transform();

    /// Reset internal state
    void reset();

    /// Extract digest into buffer
    void __getDigest(unsigned char* r);

private:
    /// Rotate left
    unsigned int rol(unsigned int value, int bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    /// Round functions (unrolled steps)
    inline void R00(int a, int b) {
        t4 += a + b + add + rol(t0, 5);
        t1 = rol(t1, 30);
    }

    inline void R01(int a, int b) {
        t0 += a + b + add + rol(t1, 5);
        t2 = rol(t2, 30);
    }

    inline void R02(int a, int b) {
        t1 += a + b + add + rol(t2, 5);
        t3 = rol(t3, 30);
    }

    inline void R03(int a, int b) {
        t2 += a + b + add + rol(t3, 5);
        t4 = rol(t4, 30);
    }

    inline void R04(int a, int b) {
        t3 += a + b + add + rol(t4, 5);
        t0 = rol(t0, 30);
    }

    /// Block expansion
    void blk();
};

#endif // __SHA_H__
