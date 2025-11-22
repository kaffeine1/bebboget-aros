/*
 * bebboget Triple-DES (DES3) implementation
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
 * Purpose: Provide Triple-DES (DES3) block cipher wrapper using
 *          Encrypt-Decrypt-Encrypt (EDE) mode with three DES keys.
 *
 * Features:
 *  - setKey(): initializes three DES contexts (A, B, C)
 *  - encrypt(): applies EDE sequence (DES-A encrypt, DES-B decrypt, DES-C encrypt)
 *  - decrypt(): applies inverse sequence (DES-C decrypt, DES-B encrypt, DES-A decrypt)
 *
 * Notes:
 *  - Triple-DES is deprecated for new designs; provided for compatibility only.
 *  - Keys are expected as 24 bytes (three 8-byte DES keys).
 * ----------------------------------------------------------------------
 */

#include "des3.h"

DES3::~DES3() {}

int DES3::setKey(const void *keyData_, unsigned keylen) {
	uint8_t *key = (uint8_t *) keyData_;
    DES::setKey(key, 8);          // First DES key
    desB.setKey(key + 8, 8);      // Second DES key
    desC.setKey(key + 16, 8);     // Third DES key
    return true;
}

void DES3::encrypt(void *cipherText_, void const *clearText_) {
	uint8_t *cipherText = (uint8_t *) cipherText_;
	uint8_t const *clearText = (uint8_t const *) clearText_;

    // Triple-DES EDE sequence: Encrypt with A, Decrypt with B, Encrypt with C
    DES::encrypt(cipherText, clearText);
    desB.decrypt(cipherText, cipherText);
    desC.encrypt(cipherText, cipherText);
}

void DES3::decrypt(void *clearText_, void const *cipherText_) {
	uint8_t const *cipherText = (uint8_t const *) cipherText_;
	uint8_t *clearText = (uint8_t *) clearText_;

    // Triple-DES inverse sequence: Decrypt with C, Encrypt with B, Decrypt with A
    desC.decrypt(clearText, cipherText);
    desB.encrypt(clearText, clearText);
    DES::decrypt(clearText, clearText);
}
