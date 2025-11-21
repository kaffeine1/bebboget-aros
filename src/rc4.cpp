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
	const byte *keyData = (const byte*) keyData_;
	int i;
	for (i = 0; i < 256; i++)
		key[i] = (byte) i;
	key[256] = 0;
	key[257] = 0;
	int index1 = 0;
	int index2 = 0;
	for (i = 0; i < 256; i++) {
		index2 = (keyData[index1] + key[i] + index2) & 0xff;
		byte t = key[i];
		key[i] = key[index2];
		key[index2] = t;
		index1 = (index1 + 1) % keylen;
	}
	return true;
}

void RC4::decrypt(void *clearText_, void const *cipherText_) {
	byte *clearText = (byte*) clearText_;
	byte const *cipherText = (byte const*) cipherText_;
	int x = key[256] & 0xff;
	int y = key[257] & 0xff;
	{
		x = (x + 1) & 0xff;
		y = (key[x] + y) & 0xff;
		byte t = key[x];
		key[x] = key[y];
		key[y] = t;
		clearText[0] = (byte) (cipherText[0] ^ key[(key[x] + key[y]) & 0xff]);
	}
	key[256] = (byte) x;
	key[257] = (byte) y;
}

void RC4::encrypt(void *cipherText_, void const *clearText_) {
	byte const *clearText = (byte const*) clearText_;
	byte *cipherText = (byte*) cipherText_;
	int x = key[256] & 0xff;
	int y = key[257] & 0xff;
	{
		x = (x + 1) & 0xff;
		y = (key[x] + y) & 0xff;
		byte t = key[x];
		key[x] = key[y];
		key[y] = t;
		cipherText[0] = (byte) (clearText[0] ^ key[(key[x] + key[y]) & 0xff]);
	}
	key[256] = (byte) x;
	key[257] = (byte) y;
}

void RC4::encryptCBC(void *iv, void *to, void const *from, unsigned long length) {
	byte const *clearText = (byte const*) from;
	byte *cipherText = (byte*) to;
	int x = key[256] & 0xff;
	int y = key[257] & 0xff;
	for (int i = 0; i < length; ++i) {
		x = (x + 1) & 0xff;
		y = (key[x] + y) & 0xff;
		byte t = key[x];
		key[x] = key[y];
		key[y] = t;
		cipherText[i] = (byte) (clearText[i] ^ key[(key[x] + key[y]) & 0xff]);
	}
	key[256] = (byte) x;
	key[257] = (byte) y;

}
void RC4::decryptCBC(void *iv, void *to, void const *from, unsigned long length) {
	encryptCBC(iv, to, from, length);
}
