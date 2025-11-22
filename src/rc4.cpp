/*
 * bebboget RC4 stream cipher implementation
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
 * Module: RC4
 *
 * Purpose:
 *  - Provide a straightforward implementation of the RC4 stream cipher
 *  - Support single-byte encrypt/decrypt and multi-byte CBC-like mode
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - RC4 is considered cryptographically broken; use only for legacy compatibility
 *  - CBC mode here is not standard RC4 usage; provided for compatibility with existing code
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include "rc4.h"

RC4::~RC4() {
}

int RC4::blockSize() const {
	return 1;
}

int RC4::setKey(const void *keyData_, unsigned keylen) {
	const uint8_t *keyData = (const uint8_t*) keyData_;
	int i;
	for (i = 0; i < 256; i++)
		key[i] = (uint8_t) i;
	key[256] = 0;
	key[257] = 0;
	int index1 = 0;
	int index2 = 0;
	for (i = 0; i < 256; i++) {
		index2 = (keyData[index1] + key[i] + index2) & 0xff;
		uint8_t t = key[i];
		key[i] = key[index2];
		key[index2] = t;
		index1 = (index1 + 1) % keylen;
	}
	return true;
}

void RC4::decrypt(void *clearText_, void const *cipherText_) {
	uint8_t *clearText = (uint8_t*) clearText_;
	uint8_t const *cipherText = (uint8_t const*) cipherText_;
	int x = key[256] & 0xff;
	int y = key[257] & 0xff;
	{
		x = (x + 1) & 0xff;
		y = (key[x] + y) & 0xff;
		uint8_t t = key[x];
		key[x] = key[y];
		key[y] = t;
		clearText[0] = (uint8_t) (cipherText[0] ^ key[(key[x] + key[y]) & 0xff]);
	}
	key[256] = (uint8_t) x;
	key[257] = (uint8_t) y;
}

void RC4::encrypt(void *cipherText_, void const *clearText_) {
	uint8_t const *clearText = (uint8_t const*) clearText_;
	uint8_t *cipherText = (uint8_t*) cipherText_;
	int x = key[256] & 0xff;
	int y = key[257] & 0xff;
	{
		x = (x + 1) & 0xff;
		y = (key[x] + y) & 0xff;
		uint8_t t = key[x];
		key[x] = key[y];
		key[y] = t;
		cipherText[0] = (uint8_t) (clearText[0] ^ key[(key[x] + key[y]) & 0xff]);
	}
	key[256] = (uint8_t) x;
	key[257] = (uint8_t) y;
}

void RC4::encryptCBC(void *iv, void *to, void const *from, unsigned long length) {
	uint8_t const *clearText = (uint8_t const*) from;
	uint8_t *cipherText = (uint8_t*) to;
	int x = key[256] & 0xff;
	int y = key[257] & 0xff;
	for (int i = 0; i < length; ++i) {
		x = (x + 1) & 0xff;
		y = (key[x] + y) & 0xff;
		uint8_t t = key[x];
		key[x] = key[y];
		key[y] = t;
		cipherText[i] = (uint8_t) (clearText[i] ^ key[(key[x] + key[y]) & 0xff]);
	}
	key[256] = (uint8_t) x;
	key[257] = (uint8_t) y;

}
void RC4::decryptCBC(void *iv, void *to, void const *from, unsigned long length) {
	encryptCBC(iv, to, from, length);
}
