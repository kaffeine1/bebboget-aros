/*
 * bebboget Secp256r1 (NIST P-256) signature verification interface
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
 * Purpose: Provide ECDSA signature verification routines for the
 *          Secp256r1 (NIST P-256) elliptic curve.
 *
 * Features:
 *  - Verify ECDSA signatures given raw signature data
 *  - Verify ECDSA signatures given r and s components
 *
 * Notes:
 *  - Secp256r1 is widely used in TLS, X.509, and JWT contexts
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SECP256R1__
#define __SECP256R1__

#include <bytearray.h>

class SecpR1 {
public:
    /// Verify ECDSA signature from raw signature data
    static int verify(bytez const& messageHash,
    		uint8_t const* sigData,
                      int len,
                      bytez const& pubk);

    /// Verify ECDSA signature from r and s components
    static int verify(bytez const& messageHash,
                      bytez const& r,
                      bytez const& s,
                      bytez const& pubk);
};

#if 0
/// Placeholder for SecpR2 curve (disabled)
class SecpR2 {
public:
    static int verify(bytez const& messageHash,
    				uint8_t const* sigData,
                      int len,
                      bytez const& pubk);
    static int verify(bytez const& messageHash,
                      bytez const& r,
                      bytez const& s,
                      bytez const& pubk);
};
#endif

#endif // __SECP256R1__
