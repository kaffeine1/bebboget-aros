/*
 * bebboget BigInteger interface
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
 *          and mathematical operations within the bebboget library.
 *
 * Features:
 *  - Construction from integers, byte arrays, and other BigInteger instances
 *  - Arithmetic operations: add, subtract, multiply, square, mod
 *  - Modular inverse and modular reduction
 *  - Bitwise shifts (left, right)
 *  - Conversion to byte arrays and string representation
 *  - Operator overloads for intuitive usage (+, -, *, %, <<, >>, &, ^)
 *
 * Notes:
 *  - Internally stores sign and used length for efficient operations
 *  - Designed for cryptographic contexts where large integer math is required
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef BIGINTEGER_H_
#define BIGINTEGER_H_

#include "fastmath32.h"

/**
 * @class BigInteger
 * @brief Arbitrary-precision integer class for bebboget.
 *
 * Provides constructors, arithmetic operations, modular math,
 * and conversion utilities for large integer values.
 */
class BigInteger {
    int usedLen;       ///< Number of words currently used
    uint32_t* n;       ///< Pointer to integer data array
    short signum;      ///< Sign of the integer (-1, 0, +1)

    /// Shrink representation starting at given offset
    void shrink(int startOffset);

public:
    /// Construct from unsigned int
    BigInteger(unsigned int i);

    /// Construct from sign and byte array
    BigInteger(short signum_, uint8_t const* ba, int len);

    /// Construct from sign and uinta container
    BigInteger(short signum_, uinta const& no);

    /// Destructor
    ~BigInteger();

    /// Move constructor
    BigInteger(BigInteger&& o);

    /// Construct from sign, raw array, and length
    BigInteger(short signum_, uint32_t* no, int usedLen);

    /// Copy constructor
    BigInteger(BigInteger const& o);

    /// Copy assignment
    BigInteger& operator=(BigInteger const& o);

    /// Move assignment
    BigInteger& operator=(BigInteger&& o);

    /// Modular inverse
    BigInteger modInverse(BigInteger const& modulo) const;

    /// Multiplication
    BigInteger multiply(BigInteger const& b) const;

    /// Modular reduction
    BigInteger mod(BigInteger const& b) const;

    /// Addition
    BigInteger add(BigInteger const& b, short overrideBSig = 0) const;

    /// Subtraction
    BigInteger subtract(BigInteger const& b, short overrideBSig = 0) const;

    /// Square
    BigInteger square() const;

    /// Left shift
    BigInteger shiftLeft(int shift) const;

    /// Right shift
    BigInteger shiftRight(int shift) const;

    /// Equality check
    int equals(BigInteger const& b) const;

    /// Convert to byte array
    bytea toByteArray() const;

    /// Convert to string
    char* toString() const;

    /// Common constants
    static BigInteger const ZERO;
    static BigInteger const ONE;
    static BigInteger const THREE;

    /// Modular reduction with special prime
    BigInteger modSecP(BigInteger const& P) const;
};

// Operator overloads for intuitive usage
inline BigInteger operator+(BigInteger const& a, BigInteger const& o) { return a.add(o); }
inline BigInteger operator-(BigInteger const& a, BigInteger const& o) { return a.subtract(o); }
inline BigInteger operator*(BigInteger const& a, BigInteger const& o) { return a.multiply(o); }
inline BigInteger operator%(BigInteger const& a, BigInteger const& o) { return a.mod(o); }

inline BigInteger operator<<(BigInteger const& a, int count) { return a.shiftLeft(count); }
inline BigInteger operator>>(BigInteger const& a, int count) { return a.shiftRight(count); }

inline BigInteger operator&(BigInteger const& a, BigInteger const& o) { return a.modSecP(o); }
inline BigInteger operator^(BigInteger const& a, int n) { return a.square(); }

#endif /* BIGINTEGER_H_ */
