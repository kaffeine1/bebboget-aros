/*
 * bebboget elliptic curve math utilities
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
 * Purpose: Provide elliptic curve math utilities for X25519 and X448
 *          key exchange and public key generation.
 *
 * Features:
 *  - x25519 and x448 Diffie-Hellman functions
 *  - Public key derivation for both curves
 *  - Private key generation
 *  - Multiplication and byte length helpers
 *  - Generic pub() to derive curve public coordinates
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __ECMATH_H__
#define __ECMATH_H__

#ifndef __BYTEARRAY_H__
#include <bytearray.h>
#endif

class ECMath {
public:
    /// Perform X25519 Diffie-Hellman exchange
    static bytea x25519(uint8_t* clientPrivateKey, uint8_t* dhg);

    /// Derive X25519 public key from private
    static void x25519Pub(uint8_t* pub, uint8_t* priv);

    /// Perform X448 Diffie-Hellman exchange
    static bytea x448(uint8_t* clientPrivateKey, uint8_t* dhg);

    /// Derive X448 public key from private
    static void x448Pub(uint8_t* pub, uint8_t* priv);

    /// Generate a private key for given curve (25519 or 448)
    static bytea genPrivateKey(int curve);

    /// Multiply curve point with private key
    static bytea multX(int curve, bytez& dhg, bytez& dhgy, bytez& clientPrivateKey);

    /// Return byte length of curve key
    static int byteLength(int curve);

    /// Derive public key coordinates for given curve
    static void pub(bytea& pubx, bytea& puby, int curve, bytez& clientPrivateKey);
};

#endif // __ECMATH_H__
