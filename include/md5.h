/*
 * bebboget MD5 message digest interface
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
 * Purpose: Provide MD5 message digest implementation derived from
 *          MessageDigest base class.
 *
 * Features:
 *  - Implements MD5 compression function (transform)
 *  - Maintains internal state (A,B,C,D words)
 *  - Provides len(), clone(), reset(), and digest extraction
 *
 * Notes:
 *  - MD5 is considered cryptographically broken; use only for legacy
 *    compatibility, not for secure applications.
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MD5_H__
#define __MD5_H__

#include <md.h>

class MD5 : public MessageDigest {
    uint32_t state0, state1, state2, state3;  ///< MD5 state words
    uint32_t t0, t1, t2, t3;                  ///< temporary registers
    uint32_t block[16];                       ///< message block buffer

public:
    /// Construct MD5 digest
    MD5();

    /// Virtual destructor
    virtual ~MD5();

    /// Return digest length (16 bytes)
    virtual unsigned len() const;

    /// Clone this digest instance
    virtual MessageDigest* clone() const;

protected:
    /// MD5 compression function
    void transform();

    /// Reset internal state
    void reset();

    /// Extract digest into buffer
    void __getDigest(unsigned char* r);

    /// Update bit count
    void addBitCount(uint64_t bitCount);

private:

    static inline uint32_t rol(uint32_t value, uint32_t bits) {
    	return (value << bits) | (value >> (32 - bits));
    }

    // Round functions
    inline void G0(uint32_t i, uint32_t a, uint32_t s, uint32_t b) {
    	t0 = t1 + rol(t0 + i + a + b, s);
    }
    inline void G1(uint32_t i, uint32_t a, uint32_t s, uint32_t b) {
    	t1 = t2 + rol(t1 + i + a + b, s);
    }
    inline void G2(uint32_t i, uint32_t a, uint32_t s, uint32_t b) {
    	t2 = t3 + rol(t2 + i + a + b, s);
    }
    inline void G3(uint32_t i, uint32_t a, uint32_t s, uint32_t b) {
    	t3 = t0 + rol(t3 + i + a + b, s);
    }

    // Boolean functions
    inline uint32_t F00() {
    	return (t3 ^ (t1 & (t2 ^ t3)));
    }
    inline uint32_t F01() {
    	return (t0 ^ (t2 & (t3 ^ t0)));
    }
    inline uint32_t F02() {
    	return (t1 ^ (t3 & (t0 ^ t1)));
    }
    inline uint32_t F03() {
    	return (t2 ^ (t0 & (t1 ^ t2)));
    }

    inline uint32_t F10() {
    	return (t2 ^ (t3 & (t1 ^ t2)));
    }
    inline uint32_t F11() {
    	return (t3 ^ (t0 & (t2 ^ t3)));
    }
    inline uint32_t F12() {
    	return (t0 ^ (t1 & (t3 ^ t0)));
    }
    inline uint32_t F13() {
    	return (t1 ^ (t2 & (t0 ^ t1)));
    }

    inline uint32_t F20() {
    	return (t1 ^ t2 ^ t3);
    }
    inline uint32_t F21() {
    	return (t2 ^ t3 ^ t0);
    }
    inline uint32_t F22() {
    	return (t3 ^ t0 ^ t1);
    }
    inline uint32_t F23() {
    	return (t0 ^ t1 ^ t2);
    }

    inline uint32_t F30() {
    	return (t2 ^ (t1 | ~t3));
    }
    inline uint32_t F31() {
    	return (t3 ^ (t2 | ~t0));
    }
    inline uint32_t F32() {
    	return (t0 ^ (t3 | ~t1));
    }
    inline uint32_t F33() {
    	return (t1 ^ (t0 | ~t2));
    }
};

#endif // __MD5_H__
