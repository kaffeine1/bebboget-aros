/*
 * bebboget ECMath skeleton (X25519 / X448)
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
 * Purpose: Provide elliptic curve math interface stubs for X25519 and X448.
 *
 * Features:
 *  - x25519(): Diffie-Hellman key exchange on Curve25519
 *  - x25519Pub(): derive public key from private key (Curve25519)
 *  - x448(): Diffie-Hellman key exchange on Curve448
 *  - x448Pub(): derive public key from private key (Curve448)
 *  - genPrivateKey(): generate private key for given curve
 *  - multX(): perform scalar multiplication for given curve
 *  - byteLength(): return key length for given curve
 *  - pub(): derive public coordinates for given curve
 *
 * Notes:
 *  - Currently stubbed; to be implemented with proper curve arithmetic.
 *  - Contributions must preserve author attribution and GPL licensing.
 * ----------------------------------------------------------------------
 */

#include <ecmath.h>

bytea ECMath::x25519(uint8_t *clientPrivateKey, uint8_t *dhg) {
    bytea x;
    return x;
}

void ECMath::x25519Pub(uint8_t *pub, uint8_t *priv) {
}

bytea ECMath::x448(uint8_t *clientPrivateKey, uint8_t *dhg) {
    bytea x;
    return x;
}

void ECMath::x448Pub(uint8_t *pub, uint8_t *priv) {
}

bytea ECMath::genPrivateKey(int curve) {
    bytea x;
    return x;
}

bytea ECMath::multX(int curve, bytez &dhg, bytez &dhgy, bytez &clientPrivateKey) {
    bytea x;
    return x;
}

int ECMath::byteLength(int curve) {
    return 0;
}

void ECMath::pub(bytea &pubx, bytea &puby, int curve, bytez &clientPrivateKey) {
}
