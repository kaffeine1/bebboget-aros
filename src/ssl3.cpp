/*
 * bebboget SSL 3.0 / TLS glue implementation
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
 * Module: Ssl3
 *
 * Purpose:
 *  - Provide SSL 3.0 / TLS protocol support for secure sockets
 *  - Implement handshake, record layer, and cipher suite negotiation
 *  - Integrate with bebboget's cryptographic library (RSA, ECDSA, AES, etc.)
 *
 * Notes:
 *  - SSL 3.0 is deprecated and insecure; TLS 1.2+ should be preferred
 *  - This implementation is maintained for compatibility and forensic analysis
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <ssl3.h>

#include <md5.h>
#include <rc4.h>
#include <des.h>
#include <des3.h>
#include <sha384.h>
#include <sha256.h>
#include <sha.h>

#include <bc.h>
#include <aes.h>
#include <gcm.h>
#include <chacha20poly1305.h>
#include <rand.h>
#include <log.h>

#undef DEBUG
#ifdef DEBUG
#if defined(__AMIGA__) && !defined(PROFILE)
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif
#endif
#include <test.h>

	// 0-1: cipher id
	// 2: key bytes;
	// 3: crypter: 0=RC4, 1=AES, 2=DES3, 3=DES, 4=AES with AEAD, 5=CHACHA20_POLY1305
	// 4: hash: 1=MD5, 2=SHA, 4=SHA256, 5=SHA384;
	// 5: key exchange: 0=DHE_DSS, 1=DHE_RSA, 2=DH_ANON 4=RSA, 5=DH_DSS, 6=DH_RSA, 7=ECDHE_RSA

const uint8_t Ssl3::TLS_CHACHA20_POLY1305_SHA256[6] = { 0x13, 0x03, 32, 5, 4, 7};
const uint8_t Ssl3::TLS_AES_256_GCM_SHA384[6] = { 0x13, 0x02, 32, 4, 5, 7 };
const uint8_t Ssl3::TLS_AES_128_GCM_SHA256[6] = { 0x13, 0x01, 16, 4, 4, 7 };
const uint8_t Ssl3::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384[6] = { 0xc0, 0x30, 32, 4, 5, 7 };
const uint8_t Ssl3::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256[6] = { 0xc0, 0x2f, 16, 4, 4, 7 };
const uint8_t Ssl3::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384[6] = { 0x00, 0x9f, 32, 4, 5, 1 };
const uint8_t Ssl3::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256[6] = { 0x00, 0x9e, 16, 4, 4, 1 };
const uint8_t Ssl3::TLS_RSA_WITH_AES_256_GCM_SHA384[6] = { 0x00, 0x9d, 32, 1, 5, 4 };
const uint8_t Ssl3::TLS_RSA_WITH_AES_128_GCM_SHA256[6] = { 0x00, 0x9c, 16, 1, 4, 4 };
const uint8_t Ssl3::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256[6] = { 0, 0x6b, 32, 1, 4, 1 };
const uint8_t Ssl3::TLS_DHE_RSA_WITH_AES_256_CBC_SHA[6] = { 0, 0x39, 32, 1, 2, 1 };
const uint8_t Ssl3::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256[6] = { 0xc0, 0x27, 16, 1, 4, 7 };
const uint8_t Ssl3::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256[6] = { 0, 0x67, 16, 1, 4, 1 };
const uint8_t Ssl3::TLS_DHE_RSA_WITH_AES_128_CBC_SHA[6] = { 0, 0x33, 16, 1, 2, 1 };
const uint8_t Ssl3::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA[6] = { 0xc0, 0x13, 16, 1, 2, 7 };
const uint8_t Ssl3::TLS_RSA_WITH_AES_256_CBC_SHA256[6] = { 0, 0x3D, 32, 1, 4, 4 };
const uint8_t Ssl3::TLS_RSA_WITH_AES_128_CBC_SHA256[6] = { 0, 0x3c, 16, 1, 4, 4 };
const uint8_t Ssl3::TLS_RSA_WITH_AES_256_CBC_SHA[6] = { 0, 0x35, 32, 1, 2, 4 };
const uint8_t Ssl3::TLS_RSA_WITH_AES_128_CBC_SHA[6] = { 0, 0x2f, 16, 1, 2, 4 };

const uint8_t Ssl3::TLS_RSA_WITH_3DES_EDE_CBC_SHA[6] = { 0, 0x0a, 24, 2, 2, 4};
const uint8_t Ssl3::TLS_RSA_WITH_DES_CBC_SHA[6] = { 0, 0x09, 8, 3, 2, 4};
const uint8_t Ssl3::TLS_RSA_WITH_RC4_128_SHA[6] = { 0, 0x05, 16, 0, 2, 4};
const uint8_t Ssl3::TLS_RSA_WITH_RC4_128_MD5[6] = { 0, 0x04, 16, 0, 1, 4};
const uint8_t Ssl3::TLS_RSA_EXPORT_WITH_RC4_40_MD5[6] = { 0, 0x03, 5, 0, 1, 4};


const uint8_t *Ssl3::CIPHERSUITES[] = {
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_DES_CBC_SHA,
		TLS_RSA_WITH_RC4_128_SHA, 0 };

const char *Ssl3::CIPHERSUITENAMES[] = {
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_DES_CBC_SHA",
		"TLS_RSA_WITH_RC4_128_SHA", 0 };

const char * Ssl3::SERVER_VFY = "TLS 1.3, server CertificateVerify";

/** a constant used in key creation. */
const uint8_t Ssl3::SERVER[] = { (uint8_t) 0x53, (uint8_t) 0x52, (uint8_t) 0x56, (uint8_t) 0x52 };

/** a constant used in key creation. */
const uint8_t Ssl3::CLIENT[] = { (uint8_t) 0x43, (uint8_t) 0x4c, (uint8_t) 0x4e, (uint8_t) 0x54 };

/** an array with length 0. */
const uint8_t Ssl3::NULLBYTES[64] = { };

const uint8_t Ssl3::SPACE32[32] = { 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
		32 };

const uint8_t Ssl3::ALERTCLOSE[] = { 1, 0 };

Ssl3::Ssl3(const uint8_t ** ciphersuites_) :
		myIn(0), myOut(0), collect(false), connected(false), ciphersuites(0),
		is(0), os(0), socket(0),
		cipherIndex(-1), md5(new MD5()), sha(new SHA()), prfMd(new SHA256()),
		rpos(0), readBufferLength(0), odd(false),
		readHash(0), writeHash(0), rhashBuffer(0), hsMd5(0), hsSha(0), readnum(0), writenum(0), cryptRead(0), cryptWrite(0),
		maxVersion(4), minVersion(1), versionMinor(0), hasEekPriv(false) {

	setCipherSuites(ciphersuites_);
}

void Ssl3::setCipherSuites(const uint8_t ** ciphersuites_) {
	int n = 0;
	while (ciphersuites_[n]) {
		++n;
	}

	delete [] ciphersuites;

	ciphersuites = new uint8_t const *[n + 1];
	ciphersuites[n] = 0;
	memcpy(ciphersuites, ciphersuites_, n * sizeof(uint8_t *));
}

Ssl3::~Ssl3() {
	clear();

	delete ciphersuites;

	delete socket;

	delete myIn;
	delete myOut;

	delete md5;
	delete sha;
	delete prfMd;

	delete readHash;
	delete writeHash;
	delete hsMd5;
	delete hsSha;
	delete cryptRead;
	delete cryptWrite;
}

void xero(bytea &v) {
	if (v.capacity()) {
		v.setSize(v.capacity());
		memset(v.begin(), 0, v.size());
	}
}

void Ssl3::clear() {
	xero(innerReadBuffer);
	xero(readBuffer);
	xero(writeBuffer);
	xero(masterSecret);

	xero(clientRandom);
	xero(serverRandom);
	xero(sessionId);
	xero(readSecret);
	xero(writeSecret);

	xero(rhashBuffer);
	xero(pendingHandshake);

	xero(readIV);
	xero(writeIV);

	memset(writeAad, 0, 13);
	memset(readAad, 0, 13);
	memset(writeNonce, 0, 12);
	memset(readNonce, 0, 12);
	memset(eekPriv, 0, 32);

	xero(serverSecret);
	xero(clientSecret);
	xero(handshakeSecret);
}

int Ssl3::readFully(uint8_t *b, int length) {
	if (length == 0)
		return true;

	int l = is->read(b, length);
	if (l <= 0)
		return false;
	while (l < length) {
		int b0 = is->read();
		if (b0 < 0)
			return false;

		b[l++] = b0;
		while (l < length) {
			int n = is->read(b + l, length - l);
			if (n <= 0) {
				r5[0] = 0;
				return false;
			}
			l += n;
		}
	}
	return true;
}

void Ssl3::calcMessageHash(uint8_t *to, MessageDigest *md, bytea &secret, unsigned long long seqNum, int typ, uint8_t *b, unsigned long blength) {

	// since TLS1.0
	if (versionMinor != 0) {
		uint8_t b13[13];
		for (int i = 0; i < 8; i++) {
			b13[i] = seqNum >> (((7 - i) * 8));
		}
		b13[8] = typ;
		b13[9] = 3;
		b13[10] = versionMinor;
		b13[11] = blength >> 8;
		b13[12] = blength;
		md->hmac(to, secret.begin(), secret.size(), b13, 13, b, blength, 0);
		return;
	}

	// SSL 3.0
	md->update(secret.begin(), secret.size());
	int count = 80 - 2 * md->len();
	uint8_t tmp[80];
	for (int i = 0; count; ++i)
		tmp[i] = 0x36;
	md->update(tmp, count);
	for (int i = 0; i < 8; i++) {
		tmp[i] = seqNum >> ((7 - i) * 8);
	}
	tmp[8] = typ;
	tmp[9] = blength >> 8;
	tmp[10] = blength;
	md->update(tmp, 11);
	md->update(b, blength);
	md->digest(to);
	md->update(secret.begin(), secret.size());
	for (int i = 0; count; ++i)
		tmp[i] = 0x5c;
	md->update(tmp, count);
	md->update(to, md->len());
	md->digest(to);
}

int Ssl3::readahead() {
	for (;;) {
		if (!readFully(r5, 5))
			break;

		if (isLogLevel(L_TRACE))
			_dump("received packet header", r5, 5);

		int len = ((r5[3] & 0xff) << 8) | (r5[4] & 0xff);
		rpos = 0;
		if (r5[1] != 3 || len <= 0) {
			// ==========================================
			// try to read a SSL2 client hello message
			if (r5[2] != 1 || r5[3] != 3)
				break;
			// emulate the 4 bytes since we just try to read the handshake
			// message header
			readBuffer.setSize(4);
			readBuffer[0] = 1;
			readBuffer[1] = 0;
			readBuffer[2] = r5[0] & 0x3f;
			readBuffer[3] = r5[1];
			readBufferLength = 4;

			r5[0] = 22; // emulate handshake type
			r5[1] = 2; // set version to 2
			return 4;
			// ==========================================
		}
		if (rhashBuffer.size()) {
			readBuffer.setSize(len);

			if (!readFully(readBuffer.begin(), len))
				return -1;
#ifdef DEBUG
			_dump("readBuffer", readBuffer.begin(), readBuffer.size());
#endif
			if (cryptRead->isAAD()) {
				readBufferLength = aeadDecrypt(r5[0], len);
				if (readBufferLength < 0)
					return SSL_ERR_READ;
				if (hasEekPriv) {
					r5[0] = readBuffer[--readBufferLength]; // patch type
				}
			} else {
				if (versionMinor > 1) {
					rpos = readIV.size();
				}

				cryptRead->decryptCBC(readIV.begin(), readBuffer.begin() + 0, readBuffer.begin() + 0, len);
#ifdef DEBUG
				_dump("readahead", readBuffer.begin(), len);
#endif
				if (cryptRead->blockSize() > 1) {
					--len;

					int pad = readBuffer[len];

					readBufferLength = len - pad - readHash->len();

					if (readBufferLength < rpos || readBufferLength >= len)
						return SSL_ERR_CORRUPT_PACKET + 100;

					if (versionMinor > 0) {
						// check padding
						for (int i = 1; i <= pad; ++i) {
							if (readBuffer[len - i] != pad) {
								return SSL_ERR_CORRUPT_PACKET + 200;
							}
						}
					}
				} else {
					readBufferLength = len - readHash->len();
				}
				uint8_t tmp[80];
				calcMessageHash(tmp, readHash, readSecret, readnum++, r5[0], readBuffer.begin() + rpos, readBufferLength - rpos);
				if (memcmp(readBuffer.begin() + readBufferLength, tmp, readHash->len())) {
					readBuffer.setSize(0);
					break;
				}
			}

			readBuffer.setSize(readBufferLength);

			// handle alerts
			if (r5[0] == 21) {
				readBufferLength = rpos;
				if (readBuffer[rpos] != 1)
					return SSL_ERR_ALERT;
				if (readBuffer[rpos + 1] == 0) {
					is->close();
					return 0;
				}
				continue;
			}

		} else {
			readBufferLength = len;
			readBuffer.setSize(len);
			if (!readFully(readBuffer.begin(), len))
				return -1;
		}
		return readBufferLength - rpos;
	}
	return -1;
}

void Ssl3::updateHandshakeHashes(uint8_t *b, unsigned length) {
	if (hsSha != 0) {
		if (hsMd5 != 0)
			hsMd5->update(b, length);
		hsSha->update(b, length);
#ifdef DEBUG
		_dump("DigestUpdate", b, length);
		auto s = hsSha->clone();
		byte x[s->len()];
		s->digest(x);
		_dump("hsSha", x, s->len());
		delete s;
#endif
	} else {
		int plen = pendingHandshake.size();
		pendingHandshake.setSize(length + plen);
		memcpy(pendingHandshake.begin() + plen, b, length);
	}
}

int Ssl3::rawread(uint8_t *b, int blen, int typ) {
	for (int i = 0; i < blen;) {
		if (rpos < readBuffer.size()) {
			int rbytes = blen;
			if (rbytes > readBuffer.size() - rpos)
				rbytes = readBuffer.size() - rpos;
			memcpy(b + i, readBuffer.begin() + rpos, rbytes);
			i += rbytes;
			rpos += rbytes;
		}
		if (i < blen) {

			const int read = readahead();
			if (read <= 0) {
				return -1;
			}
			if (r5[0] != typ) {
				if (r5[0] == 0) {
					return 0;
				}
				if (r5[0] == 21) // alert!
						{
					// close of connection received?
					if (readBuffer[0] == 1 && readBuffer[1] == 0) {
						return 0;
					}
					return SSL_ERR_ALERT;
				}
				if (r5[0] == 22) { // some handshake message!?
					int len = r5[3] & 0xff;
					len = (len << 8) | (r5[4] & 0xff);
					updateHandshakeHashes(readBuffer.begin() + rpos, len);
					rpos += len;
				} else
					return -1;
			}
		}
	}
	// test r5[0] since TLS1.3 will patch this
	if (collect && r5[0] == 22) {
		// cumulate handshake messages
		updateHandshakeHashes(b + 0, blen);
	}
	return blen;
}

int Ssl3::read() {
	uint8_t onebyte[2];
	if (1 != rawread(onebyte, 1, 23))
		return -1;
	return onebyte[0];
}

int Ssl3::aeadDecrypt(int typ, unsigned len) {
	AeadBlockCipher *aead = (AeadBlockCipher*) cryptRead;

	uint8_t *r = readBuffer.begin();
#ifdef DEBUG
		_dump("AEAD packet in: ", readBuffer.begin(), len);
#endif

	int off;
	if (hasEekPriv) {
		unsigned long long rn = readnum > 0 ? readnum - 1 : 0;
		rn ^= readnum++;
		for (int i = 0; rn != 0 && i < readIV.size(); ++i) {
			readIV[readIV.size() - i - 1] ^= rn;
			rn >>= 8;
		}
		aead->init(readIV.begin(), readIV.size());
		aead->updateHash(r5, 5);
		off = 0;
		len -= 16;
	} else {
		readNonce[4] = r[0];
		readNonce[5] = r[1];
		readNonce[6] = r[2];
		readNonce[7] = r[3];
		readNonce[8] = r[4];
		readNonce[9] = r[5];
		readNonce[10] = r[6];
		readNonce[11] = r[7];

		aead->init(readNonce, 12);
//			if (DEBUG.ON)
//				Misc.dump("read nonce: ", System.out, readNonce, 0, 12);

		len -= 24;
		off = 8;

		readAad[8] = typ;
		readAad[11] = (len >> 8);
		readAad[12] = len;
		aead->updateHash(readAad, sizeof(readAad));

//			if (DEBUG.ON)
//				Misc.dump("read aad: ", System.out, readAad, 0, 13);

		// inc counter
		for (int i = 7; i >= 0; --i)
			if (++readAad[i] != 0)
				break;
	}

	aead->decrypt(r, r + off, len);

#ifdef DEBUG
	_dump("decoded AEAD packet: ",  r, len);
#endif

	// append hash
	uint8_t t16[16];
	aead->calcHash(t16);

#ifdef DEBUG
	_dump("AEAD hash: ", t16, 16);
#endif

	if (memcmp(t16, r + len + off, 16))
		return -1;

	return len;
}

void Ssl3::addHandshakeHeader(int msgType, uint8_t *b, unsigned length) {
	int offset = 0;
	b[offset] = (uint8_t) msgType;
	b[offset + 1] = (uint8_t) (length >> 16);
	b[offset + 2] = (uint8_t) (length >> 8);
	b[offset + 3] = (uint8_t) (length);

	length += 4;

	updateHandshakeHashes(b, length);
}

void Ssl3::addMessageHeader(int packetType, uint8_t *b, unsigned length) {
	int offset = 0;
	b[offset] = packetType;
	b[offset + 1] = 3; // version
	b[offset + 2] = versionMinor;
	b[offset + 3] = (length >> 8);
	b[offset + 4] = (length);
}

int Ssl3::innerRead() {
	int len = ((head[1] & 0xff) << 16) | ((head[2] & 0xff) << 8) | (head[3] & 0xff);
	logme(L_DEBUG, "innerRead: len=%ld", len);

	if (r5[1] == 2) { // got an emulated version 2 packet?
					  // ==========================================
					  // try to read a SSL2 client hello message
		--len;
		innerReadBuffer.setSize(len);
		uint8_t *b = innerReadBuffer.begin();

		b[0] = r5[3];
		b[1] = r5[4];
		for (int l = 2; l < len;) {
			int r = is->read(b + l, len - l); // read the rest
			if (r <= 0)
				return -1;
			l += r;
		}

		pendingHandshake.setSize(0);
		if (hsSha != 0) {
			if (hsMd5 != 0) {
				hsMd5->reset();
			}
			hsSha->reset();
		}

		updateHandshakeHashes(r5 + 2, 1);
		updateHandshakeHashes(b + 0, len);

		// Trace.dump(System.out, r5);
		// Trace.dump(System.out, b);

		b[0] = 2; // it's a version 2 handshake!
		return len;
		// ==========================================
	}
	innerReadBuffer.setSize(len);
	if (len == 0)
		return 0;

	if (len != rawread(innerReadBuffer.begin(), len, 22))
		return -1;

	return len;
}

int Ssl3::hs_read(int msgType) {
	int rlen = rawread(head, 4, 22);
	if (4 != rlen || msgType != head[0])
		return -1;
	if (isLogLevel(L_TRACE))
		_dump("read packet header", head, 4);

	return innerRead();

}

void Ssl3::startHandshakeHashes(int selectedChiperSuite) {
#ifdef DEBUG
		    _dump("hashing handshake messages", pendingHandshake.begin(), pendingHandshake.size());
#endif

	if (versionMinor >= 3) {
		delete prfMd;
		delete hsSha;
		switch (ciphersuites[selectedChiperSuite][4]) {
		case 5:
			prfMd = new SHA384();
			hsSha = new SHA384();
			break;
		case 4:
			prfMd = new SHA256();
			hsSha = new SHA256();
			break;
		default:
			prfMd = new SHA();
			hsSha = new SHA();
			break;
		}
	} else {
		delete hsMd5;
		delete hsSha;
		hsMd5 = new MD5();
		hsSha = new SHA();
		hsMd5->update(pendingHandshake.begin(), pendingHandshake.size());
	}
	hsSha->update(pendingHandshake.begin(), pendingHandshake.size());
#ifdef DEBUG
	printf("hsSha %08ld\n", hsSha);
	auto s = hsSha->clone();
	byte x[s->len()];
	s->digest(x);
	_dump("hsSha", x, s->len());
	delete s;
#endif
	pendingHandshake.setSize(0);
}

void Ssl3::createTls13EarlyKeys(int isServer) {
	logme(L_DEBUG, "create early TLS1.3 keys");

	delete cryptRead;
	delete cryptWrite;
	delete readHash;
	delete writeHash;

	const uint8_t *cs = ciphersuites[cipherIndex];
	int keyLen = cs[2];
	if (cs[3] == BC_CHACHA20_POLY1305) {
		cryptRead = new ChaCha20Poly1305();
		cryptWrite = new ChaCha20Poly1305();
	} else {
		cryptRead = new GCM(new AES(keyLen));
		cryptWrite = new GCM(new AES(keyLen));
	}

	switch (cs[4]) {
	case 4:
		this->readHash = new SHA256();
		this->writeHash = new SHA256();
		break;
	case 5:
		this->readHash = new SHA384();
		this->writeHash = new SHA384();
		break;
	default:
		this->readHash = new SHA();
		this->writeHash = new SHA();
		break;
	}

#ifdef DEBUG
	printf("hsSha %08ld\n", hsSha);
#endif
	uint8_t helloHash[hsSha->len()];
	auto s = hsSha->clone();
	s->digest(helloHash);
	delete s;

	int hashLen = readHash->len();
	uint8_t earlySecret[hashLen];
	memset(earlySecret, 0, hashLen);
	readHash->hmac(earlySecret, NULLBYTES, 1, NULLBYTES, hashLen, 0);

	uint8_t emptyHash[hashLen];
	readHash->digest(emptyHash);

	uint8_t derivedSecret[hashLen];
	readHash->expandLabel(derivedSecret, hashLen, earlySecret, hashLen, "tls13 derived", 13, emptyHash, hashLen);

	handshakeSecret.setSize(hashLen);
	readHash->hmac(handshakeSecret.begin(), derivedSecret, hashLen, masterSecret.begin(), masterSecret.size(), 0);

	clientSecret.setSize(hashLen);
	readHash->expandLabel(clientSecret.begin(), hashLen, handshakeSecret.begin(), hashLen, "tls13 c hs traffic", 18, helloHash, hashLen);

	serverSecret.setSize(hashLen);
	readHash->expandLabel(serverSecret.begin(), hashLen, handshakeSecret.begin(), hashLen, "tls13 s hs traffic", 18, helloHash, hashLen);

	uint8_t clientKey[keyLen];
	readHash->expandLabel(clientKey, keyLen, clientSecret.begin(), hashLen, "tls13 key", 9, NULLBYTES, 0);

	uint8_t serverKey[keyLen];
	readHash->expandLabel(serverKey, keyLen, serverSecret.begin(), hashLen, "tls13 key", 9, NULLBYTES, 0);

	uint8_t * clientIv;
	uint8_t * serverIv;

	readIV.setSize(12);
	writeIV.setSize(12);

	// set cryptkeys
	if (isServer) {
		cryptRead->setKey(clientKey, keyLen);
		cryptWrite->setKey(serverKey, keyLen);
		clientIv = readIV.begin();
		serverIv = writeIV.begin();
	} else {
		cryptRead->setKey(serverKey, keyLen);
		cryptWrite->setKey(clientKey, keyLen);
		serverIv = readIV.begin();
		clientIv = writeIV.begin();
	}

	readHash->expandLabel(clientIv, 12, clientSecret.begin(), hashLen, "tls13 iv", 8, NULLBYTES, 0);
	readHash->expandLabel(serverIv, 12, serverSecret.begin(), hashLen, "tls13 iv", 8, NULLBYTES, 0);

#ifdef DEBUG
_dump("helloHash", helloHash, hsSha->len());
_dump("earlySecret", earlySecret, hashLen);
_dump("emptyHash", emptyHash, hashLen);
_dump("derivedSecret", derivedSecret, hashLen);
_dump("handshakeSecret", handshakeSecret.begin(), hashLen);
_dump("clientSecret", clientSecret.begin(), hashLen);
_dump("serverSecret", serverSecret.begin(), hashLen);
_dump("clientKey", clientKey, keyLen);
_dump("serverKey", serverKey, keyLen);
_dump("clientIv", clientIv, 12);
_dump("serverIv",  serverIv, 12);
#endif

}

bytea Ssl3::createTls13HandshakeFinished(MessageDigest *md, bytea const &secret) {
	logme(L_DEBUG, "calculate TLS1.3 handshake finished");

	int l = md->len();
	uint8_t finishedHash[l];
	md->digest(finishedHash);

	uint8_t finishedKey[l];
	md->expandLabel(finishedKey, l, secret.begin(), secret.size(), "tls13 finished", 14, 0, 0);

	bytea verifyData;
	verifyData.setSize(l);
	md->hmac(verifyData.begin(), finishedKey, l, finishedHash, l, 0);
	return verifyData;
}

int Ssl3::aeadEncrypt(uint8_t *b, unsigned len, int typ) {
	AeadBlockCipher *gcm = (AeadBlockCipher*) cryptWrite;
	int inOff;
	if (hasEekPriv) {
		// copy data since we append a byte, use the write buffer and an even address
		writeBuffer.setSize(len + 36);
		memcpy(writeBuffer.begin() + 32, b, len);
		writeBuffer[32 + len] = (uint8_t) typ;
		inOff = 32;
		b = writeBuffer.begin();
		++len;
	} else
		inOff = 0;

	unsigned elen;
	if (hasEekPriv)
		elen = len + 16; // + hash + typ is part of b!
	else
		elen = len + 8 + 16; // iv + hash

	unsigned outLen = elen + 5; // header
	writeBuffer.setSize(outLen);

	uint8_t *w = writeBuffer.begin();
	w[1] = (uint8_t) 3; // version
	w[3] = (uint8_t) (elen >> 8);
	w[4] = (uint8_t) (elen);

	int off;
	if (hasEekPriv) {
		w[0] = 0x17;
		w[2] = 3;

		unsigned long long wn = writenum > 0 ? writenum - 1 : 0;
		wn ^= writenum++;
		for (int i = 0; wn != 0 && i < writeIV.size(); ++i) {
			writeIV[writeIV.size() - i - 1] ^= (uint8_t) wn;
			wn >>= 8;
		}
		gcm->init(writeIV.begin(), writeIV.size());
		gcm->updateHash(w, 5);

		off = 5;
	} else {
		w[0] = (uint8_t) typ;
		w[2] = versionMinor;

		w[5] = writeNonce[4];
		w[6] = writeNonce[5];
		w[7] = writeNonce[6];
		w[8] = writeNonce[7];
		w[9] = writeNonce[8];
		w[10] = writeNonce[9];
		w[11] = writeNonce[10];
		w[12] = writeNonce[11];

		gcm->init(writeNonce, 12);

#ifdef DEBUG
	_dump("write nonce: ", writeNonce, 12);
#endif
		for (int i = 11; i >= 4; --i)
			if (++writeNonce[i] != 0)
				break;

//				laufende nummer 8 bytes
//				type   22 (packet type)
//				major
//				minor
//				hi(len)   des Pakets - ohne expl iv
//				lo(len)

		writeAad[8] = (uint8_t) typ;
		writeAad[11] = (uint8_t) (len >> 8);
		writeAad[12] = (uint8_t) len;
		gcm->updateHash(writeAad, 13);
#ifdef DEBUG
		_dump("write aad: ", writeAad, 13);
#endif
		// inc counter
		for (int i = 7; i >= 0; --i)
			if (++writeAad[i] != 0)
				break;

		off = 13;
	}

	odd = off & 1;
	if (odd) {
		memmove(w + 1, w, off);
		++w;	// w + off is even
	}

	gcm->encrypt(w + off, b + inOff, len);

	// append hash
#ifdef __mc68020__
	gcm->calcHash(w + len + off);
#else
	uint32_t x[4];
	gcm->calcHash(x);
	memcpy(w + len + off, x, 16);
#endif

#ifdef DEBUG
_dump("AEAD packet: ",  writeBuffer.begin(),  outLen);
#endif
	return outLen;
}

int Ssl3::rawwrite(uint8_t *b, unsigned len, int typ) {
	logme(L_DEBUG, "rawwrite len=%ld kind=%ld", len, typ);
	if (isLogLevel(L_ULTRA)) {
		_dump("rawrite", b, len);
	}

	if (cryptWrite->isAAD()) {
		int outLen = aeadEncrypt(b, len, typ);
		if (outLen < 0)
			return outLen;

		return os->write(writeBuffer.begin() + odd, outLen);
	}

	int offset = 0;
	bytea tmp;
	if (versionMinor > 1 && writeIV.size() > 0) {
		// add a random explicit writeIV - since TLS 1.1
		offset = writeIV.size();

		tmp.setSize(len + offset);
		randfill(tmp.begin(), offset);
//		if (DEBUG.USE_TEST_DATA)
//			for (int ii = 0; ii < offset; ++ii)
//				tmp[ii] = (uint8_t) ii;

		memcpy(tmp.begin() + offset, b, len);

		b = tmp.begin();
		len = tmp.size();
	}

	int hashLen = writeHash->len();
	bytes(hb, hashLen);
	calcMessageHash(hb.begin(), writeHash, writeSecret, writenum++, typ, b + offset, len - offset);

	offset += 5;
	// without padding
	unsigned blockSize = cryptRead->blockSize();
	if (blockSize == 1) {
		unsigned useLen = len + hashLen;
		int outLen = useLen + 5;
		writeBuffer.setSize(outLen);

		uint8_t *w = writeBuffer.begin();
		w[0] = (uint8_t) typ;
		w[1] = (uint8_t) 3; // version
		w[2] = versionMinor;
		w[3] = (uint8_t) ((useLen) >> 8);
		w[4] = (uint8_t) (useLen);

		cryptWrite->encryptCBC(writeIV.begin(), w + offset, b, len);
		cryptWrite->encryptCBC(writeIV.begin(), w + offset + len, hb.begin(), hashLen);
		return os->write(w, outLen);
	}

	writeBuffer.setSize(5 + len + hashLen + blockSize);
	uint8_t *w = writeBuffer.begin();
	memcpy(w + 5, b, len);
	memcpy(w + 5 + len, hb.begin(), hashLen);

	// add the padding to the length
	int pad = 0;
	len += hashLen;
	int rem = (len + 1) % blockSize;
	pad = blockSize - rem;
	if (pad == blockSize)
		pad = 0;
	len += pad + 1;

	int outLen = len + 5;

	w[0] = (uint8_t) typ;
	w[1] = (uint8_t) 3; // version
	w[2] = versionMinor;
	w[3] = (uint8_t) (len >> 8);
	w[4] = (uint8_t) (len);

	for (int i = 1; i <= pad; ++i) {
		w[len - i + 4] = (uint8_t) pad; // secureRnd.next(8);
	}
	w[len + 4] = (uint8_t) pad;
#ifdef DEBUG
	_dump("write", w + 5, len);
#endif
	cryptWrite->encryptCBC(writeIV.begin(), w + 5, w + 5, len);
#ifdef DEBUG
	_dump("write cbc", w, outLen);
#endif
	return os->write(w, outLen);
}

void Ssl3::createTls13Keys(int isServer, MessageDigest *lastHsHash) {
	logme(L_DEBUG, "create TLS1.3 keys");

	delete cryptRead;
	delete cryptWrite;
	delete readHash;
	delete writeHash;

	const uint8_t *cs = ciphersuites[cipherIndex];
	int keyLen = cs[2];
	if (cs[3] == BC_CHACHA20_POLY1305) {
		cryptRead = new ChaCha20Poly1305();
		cryptWrite = new ChaCha20Poly1305();
	} else {
		cryptRead = new GCM(new AES(keyLen));
		cryptWrite = new GCM(new AES(keyLen));
	}

	switch (cs[4]) {
	case 4:
		this->readHash = new SHA256();
		this->writeHash = new SHA256();
		break;
	case 5:
		this->readHash = new SHA384();
		this->writeHash = new SHA384();
		break;
	default:
		this->readHash = new SHA();
		this->writeHash = new SHA();
		break;
	}

	bytes(handshakeHash, lastHsHash->len());
	lastHsHash->digest(handshakeHash.begin());

	int hashLen = readHash->len();
	bytes(emptyHash, hashLen);
	readHash->digest(emptyHash.begin());

	bytes(derivedSecret, hashLen);
	readHash->expandLabel(derivedSecret.begin(), derivedSecret.size(), handshakeSecret.begin(), handshakeSecret.size(), "tls13 derived", 13, emptyHash.begin(),
			hashLen);

	masterSecret.setSize(hashLen);
	readHash->hmac(masterSecret.begin(), derivedSecret.begin(), derivedSecret.size(), NULLBYTES, hashLen, 0);

//    	Misc.dump("masterSecret", System.out, masterSecret);

	clientSecret.setSize(hashLen);
	readHash->expandLabel(clientSecret.begin(), clientSecret.size(), masterSecret.begin(), masterSecret.size(), "tls13 c ap traffic", 18, handshakeHash.begin(),
			handshakeHash.size());
	serverSecret.setSize(hashLen);
	readHash->expandLabel(serverSecret.begin(), serverSecret.size(), masterSecret.begin(), masterSecret.size(), "tls13 s ap traffic", 18, handshakeHash.begin(),
			handshakeHash.size());

	bytes(clientKey, keyLen);
	readHash->expandLabel(clientKey.begin(), clientKey.size(), clientSecret.begin(), clientSecret.size(), "tls13 key", 9, NULLBYTES, 0);
	bytes(serverKey, keyLen);
	readHash->expandLabel(serverKey.begin(), serverKey.size(), serverSecret.begin(), serverSecret.size(), "tls13 key", 9, NULLBYTES, 0);

	uint8_t * clientIv;
	uint8_t * serverIv;

	readIV.setSize(12);
	writeIV.setSize(12);

	// set cryptkeys
	if (isServer) {
		cryptRead->setKey(clientKey.begin(), clientKey.size());
		cryptWrite->setKey(serverKey.begin(), serverKey.size());
		clientIv = readIV.begin();
		serverIv = writeIV.begin();
	} else {
		cryptRead->setKey(serverKey.begin(), serverKey.size());
		cryptWrite->setKey(clientKey.begin(), clientKey.size());
		serverIv = readIV.begin();
		clientIv = writeIV.begin();
	}

	readHash->expandLabel(clientIv, 12, clientSecret.begin(), clientSecret.size(), "tls13 iv", 8, NULLBYTES, 0);
	readHash->expandLabel(serverIv, 12, serverSecret.begin(), serverSecret.size(), "tls13 iv", 8, NULLBYTES, 0);

#ifdef DEBUG
_dump("handshakeHash", handshakeHash.begin(), hsSha->len());
_dump("emptyHash", emptyHash.begin(), hashLen);
_dump("derivedSecret", derivedSecret.begin(), hashLen);
_dump("handshakeSecret", handshakeSecret.begin(), hashLen);
_dump("clientSecret", clientSecret.begin(), hashLen);
_dump("serverSecret", serverSecret.begin(), hashLen);
_dump("clientKey", clientKey.begin(), keyLen);
_dump("serverKey", serverKey.begin(), keyLen);
_dump("clientIv", clientIv, 12);
_dump("serverIv",  serverIv, 12);
#endif


	readnum = writenum = 0;
}

static bytea pHash(int length, MessageDigest *md, bytez &secret, bytez &seed) {

	bytes(ai, md->len());
	bytes(d, md->len());

	bytez *aip = &seed;

	bytea r(length);

#ifdef DEBUG
_dump("secret", secret.begin(), secret.size());
_dump("seed", seed.begin(), seed.size());
#endif

	int pos = 0;
	while (pos < length) {
		md->hmac(ai.begin(), secret.begin(), secret.size(), aip->begin(), aip->size(), 0);
#ifdef DEBUG
		_dump("ai", ai.begin(), ai.size());
#endif
		aip = &ai;
		md->hmac(d.begin(), secret.begin(), secret.size(), aip->begin(), aip->size(), seed.begin(), seed.size(), 0);
		int copyLen = d.size();
		if (pos + copyLen > length)
			copyLen = length - pos;
		memcpy(r.begin() + pos, d.begin(), copyLen);
		pos += copyLen;
	}

	// Misc.dump("result", System.out, r);
	return r;
}

bytea Ssl3::PRF(int length, bytez &secret, char const *id, int idlen, bytez &add1, bytez &add2) {

	bytes(data, idlen + add1.size() + add2.size());
	strcpy((char*) data.begin(), id);
	memcpy(data.begin() + idlen, add1.begin(), add1.size());
	memcpy(data.begin() + idlen + add1.size(), add2.begin(), add2.size());

#ifdef DEBUG
		_dump("PRF IN", data.begin(), data.size());
		printf("versionMinor %ld\n",versionMinor);
#endif

	bytea r;
	if (versionMinor < 3) {
		// SSL3.0 - TLS 1.1
		// get the 2 halves of the preMasterSecret
		int partLen = (secret.size() + 1) >> 1;
		bytes(md5Secret, partLen);
		bytes(shaSecret, partLen);
		memcpy(md5Secret.begin(), secret.begin(), partLen);
		memcpy(shaSecret.begin(), secret.begin() + secret.size() - partLen, partLen);
		r = pHash(length, sha, shaSecret, data);
		bytea r1 = pHash(length, md5, md5Secret, data);
		for (int i = 0; i < length; ++i) {
			r[i] ^= r1[i];
		}
	} else {
		// TLS 1.2 is using SHA only /?
		r = pHash(length, prfMd, secret, data);
	}
#ifdef DEBUG
		_dump("PRF", r.begin(), r.size());
#endif
	return r;
}

bytea Ssl3::makeHashBytes(bytez &x, int n, bytez &ra, bytez &input) {
	int sz = (n + 15) & ~15;
	bytea r(sz);
	r.setSize(n);

	bytes(ja, sz / 16 + 1);
	bytes(tmp, 20);

	for (int i = 0; i * 16 < n; ++i) {
		for (int j = 0; j <= i; ++j)
			ja[j] = 0x41 + i;

		sha->update(ja.begin(), i + 1);

//		if (DEBUG.HANDSHAKEHASH)
//			Misc.dump("mhb1: ", System.out, sha.clone().digest());
		sha->update(x.begin(), x.size());
//		if (DEBUG.HANDSHAKEHASH)
//			Misc.dump("mhb2: ", System.out, sha.clone().digest());
		sha->update(ra.begin(), ra.size());
//		if (DEBUG.HANDSHAKEHASH)
//			Misc.dump("mhb3: ", System.out, sha.clone().digest());
		sha->update(input.begin(), input.size());
//		if (DEBUG.HANDSHAKEHASH)
//			Misc.dump("mhb4: ", System.out, sha.clone().digest());
		sha->digest(tmp.begin());

		md5->update(x.begin(), x.size());
//		if (DEBUG.HANDSHAKEHASH)
//			Misc.dump("mhb5: ", System.out, md5.clone().digest());
		md5->update(tmp.begin(), 20);
//		if (DEBUG.HANDSHAKEHASH)
//			Misc.dump("mhb6: ", System.out, md5.clone().digest());
		md5->digest(r.begin() + i * 16);
	}
	return r;
}

void Ssl3::createKeys(int isServer) {
	logme(L_DEBUG, "create SSL/TLS keys");

	delete readHash;
	delete writeHash;
	delete cryptRead;
	delete cryptWrite;

	const uint8_t *cs = ciphersuites[cipherIndex];
	int keyLen = cs[2];
	switch (cs[4]) {
	case 1:
		readHash = new MD5();
		writeHash = new MD5();
		break;
	case 4:
		readHash = new SHA256();
		writeHash = new SHA256();
		break;
	case 5:
		readHash = new SHA384();
		writeHash = new SHA384();
		break;
	default:
		readHash = new SHA();
		writeHash = new SHA();
		break;
	}

	int hashLen = readHash->len();

	switch (cs[3]) {
	case 0:
		cryptRead = new RC4();
		cryptWrite = new RC4();
		break;
	case 2:
		cryptRead = new DES3();
		cryptWrite = new DES3();
		break;
	case 3:
		cryptRead = new DES();
		cryptWrite = new DES();
		break;
	case 4:
		cryptRead = new GCM(new AES(keyLen));
		cryptWrite = new GCM(new AES(keyLen));
		hashLen = 0;
		memset(writeAad, 0, 13);
		writeAad[9] = 3;
		writeAad[10] = versionMinor;
		memset(readAad, 0, 13);
		readAad[9] = 3;
		readAad[10] = versionMinor;
		break;
	case 5:
		cryptRead = new ChaCha20Poly1305;
		cryptWrite = new ChaCha20Poly1305;
		hashLen = 0;
		memset(writeAad, 0, 13);
		writeAad[9] = 3;
		writeAad[10] = versionMinor;
		memset(readAad, 0, 13);
		readAad[9] = 3;
		readAad[10] = versionMinor;
		break;
	default:
		cryptRead = new AES(keyLen);
		cryptWrite = new AES(keyLen);
		break;
	}

	readSecret.setSize(hashLen);
	writeSecret.setSize(hashLen);
	int blockSize = cryptRead->blockSize();
	if (blockSize == 1) {
		readIV.setSize(0);
		writeIV.setSize(0);
	} else {
		readIV.setSize(blockSize);
		writeIV.setSize(blockSize);
	}

	// calculate the keys
	bytes(srk, keyLen);
	bytes(swk, keyLen);

	int keyMaterialLength = 2 * (hashLen + keyLen);
	// add room for implicit IVs
	keyMaterialLength += readIV.size() + readIV.size();
	bytea ba;
	if (versionMinor != 0) {
		ba = PRF(keyMaterialLength, masterSecret, "key expansion", 13, serverRandom, clientRandom);
	} else {
		ba = makeHashBytes(masterSecret, keyMaterialLength, serverRandom, clientRandom);
	}

	{
		uint8_t *b = ba.begin();

		memcpy(isServer ? readSecret.begin() : writeSecret.begin(), b, hashLen);
		b += hashLen;
		memcpy(isServer ? writeSecret.begin() : readSecret.begin(), b, hashLen);
		b += hashLen;

		memcpy(srk.begin(), b, keyLen);
		b += keyLen;
		memcpy(swk.begin(), b, keyLen);
		b += keyLen;

		memcpy(isServer ? readIV.begin() : writeIV.begin(), b, readIV.size());
		b += readIV.size();
		memcpy(isServer ? writeIV.begin() : readIV.begin(), b, readIV.size());
		b += readIV.size();
	}
	// export version: recalculate the final keys
	if (keyLen < 16) {
		md5->update(srk.begin(), srk.size());
		md5->update(clientRandom.begin(), clientRandom.size());
		md5->update(serverRandom.begin(), serverRandom.size());
		md5->digest(srk.begin());
		srk.setSizeValue(16);

		md5->update(swk.begin(), swk.size());
		md5->update(serverRandom.begin(), serverRandom.size());
		md5->update(clientRandom.begin(), clientRandom.size());
		md5->digest(swk.begin());
		swk.setSizeValue(16);
	}
	// set cryptkeys
	if (isServer) {
		cryptRead->setKey(srk.begin(), srk.size());
		cryptWrite->setKey(swk.begin(), swk.size());
	} else {
		cryptRead->setKey(swk.begin(), swk.size());
		cryptWrite->setKey(srk.begin(), srk.size());
	}

	if (cryptRead->isAAD()) {
		writeNonce[0] = writeIV[0];
		writeNonce[1] = writeIV[1];
		writeNonce[2] = writeIV[2];
		writeNonce[3] = writeIV[3];
		randfill(writeNonce + 4, 8);

		readNonce[0] = readIV[0];
		readNonce[1] = readIV[1];
		readNonce[2] = readIV[2];
		readNonce[3] = readIV[3];
		memset(readNonce + 4, 0, 8);
	}
#ifdef DEBUG
	_dump("readSecret", readSecret.begin(), readSecret.size());
	_dump("writeSecret", writeSecret.begin(), writeSecret.size());
	_dump("srk", srk.begin(), srk.size());
	_dump("swk", swk.begin(), swk.size());
	_dump("readIV", readIV.begin(), readIV.size());
	_dump("writeIV", writeIV.begin(), writeIV.size());

	if (cryptRead->isAAD()) {
		_dump("readNonce", readNonce, 12);
		_dump("writeNonce", writeNonce, 12);
	}
#endif
}

void Ssl3::calc_hs_hash(void *to, MessageDigest *md, int len, bytez &sender) {
	md->update(sender.begin(), sender.size()); // handshake + sender
	md->update(masterSecret.begin(), masterSecret.size()); // handshake + sender + mastersecret

	bytes(t, len);
	for (int i = 0; i < len; ++i)
		t[i] = 0x36;
	md->update(t.begin(), t.size()); // handshake + sender + mastersecret + pad1

	bytes(b, md->len());
	md->digest(b.begin());

	md->update(masterSecret.begin(), masterSecret.size());

	for (int i = 0; i < len; ++i)
		t[i] = 0x5c;
	md->update(t.begin(), t.size()); // masterSecret + pad2

	md->update(b.begin(), b.size());
	md->digest(to);
	// masterSecret + pad2 + md5(handshake + sender + mastersecret + pad1)
}

bytea Ssl3::finishedHash(char const *cs, uint8_t const *csData) {
	// calculate the hashes for the client finished masterSecret
	if (versionMinor != 0) {
		// TLS
		bytes(hsNowMd5, hsMd5 ? 16 : 0);
		if (hsMd5) {
			MessageDigest *md = hsMd5->clone();
			md->digest(hsNowMd5.begin());
			delete md;
		}

		bytes(hsNowSha, hsSha->len());
		{
			MessageDigest *md = hsSha->clone();
			md->digest(hsNowSha.begin());
			delete md;
		}
		bytea h = PRF(12, masterSecret, cs, strlen(cs), hsNowMd5, hsNowSha);
#ifdef DEBUG
		_dump("finishedHash:h", h.begin(), h.size());
#endif
		bytea b(16);
		b[0] = b[1] = b[2] = b[3] = 0;
		memcpy(b.begin() + 4, h.begin(), 12);

#ifdef DEBUG
		_dump("finishedHash", b.begin(), b.size());
#endif

		return b;
	}
	// SSL 3.0
	bytes(cmd5hash, 16);
	MessageDigest *md = hsMd5->clone();

	bytez x((void*) csData, 4);
	calc_hs_hash(cmd5hash.begin(), md, 48, x);
	delete md;

	bytes(cshahash, 20);
	md = hsSha->clone();
	calc_hs_hash(cshahash.begin(), md, 40, x);
	delete md;

	bytea h;
	h.setSize(40);
	memcpy(h.begin() + 4, cmd5hash.begin(), 16);
	memcpy(h.begin() + 20, cshahash.begin(), 20);
	return h;
}

int Ssl3::write(bytez &b) {
	const int maxFragmentLength = 1 << 14;
	if (b.size() <= maxFragmentLength) {
		if (rawwrite(b.begin(), b.size(), 23) > b.size())
			return b.size();
		return -1;
	}
	int off = 0;
	while (off < b.size()) {
		int out = b.size() - off;
		if (out > maxFragmentLength) {
			out = maxFragmentLength;
		}
		if (rawwrite(b.begin() + off, out, 23) <= 0)
			break;
		off += out;
	}
	return off;
}

int Ssl3::available() {
	if (rpos < readBufferLength)
		return readBufferLength - rpos;
	if (is->available() < 4 + readHash->len())
		return 0;
	int r = readahead();
	if (r <= 0)
		return -1;

	return readBufferLength - rpos;
}

int Ssl3::read(bytez &ba) {
	int len = available();
	// System.err.println("avail " + len);
	if (len < 0)
		return -1;

	if (len == 0)
		len = 1;

	if (len > ba.size())
		len = ba.size();
	// System.err.println("reading " + len);
	return rawread(ba.begin(), len, 23);
}

class SslOutputStream: public io::OutputStream {
	/** the used SSL instance. */
	Ssl3 *ssl;
	/** buffer to write a single byte. */
	uint8_t one[1];

public:
	/**
	 * Creates a new object for writing to a Ssl2 connection.
	 * @param ssl the used SSL connection to write to
	 */
	SslOutputStream(Ssl3 *ssl_) :
			ssl(ssl_) {
	}

	/**
	 * Writes the given byte to the output stream.
	 * @param b the byte to write
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	virtual int write(int b) {
		if (!ssl->isConnected())
			return -1;
		bytes(one, 1);
		one[0] = (uint8_t) b;
		return ssl->write(one);
	}

	/**
	 * Writes the given byte array to the output stream.
	 * @param x the buffer which is written.
	 * @param off the offset into the array
	 * @param len the count of bytes to write
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	int write(void const *buffer, int len) {
		if (!ssl->isConnected())
			return -1;
		bytez x(buffer, len);
		return ssl->write(x);
	}

	/**
	 * Closes this output stream and releases any system resources associated with the stream.
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	int close() {
		// ssl->close();
		return 0;
	}
	/**
	 * Flushes this output stream.
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	int flush() {
		return 0;
	}
};

io::OutputStream* Ssl3::getOutputStream() {
	if (!myOut)
		myOut = new SslOutputStream(this);
	return myOut;
}

class SslInputStream: public io::InputStream {
	/** the used ssl instance. */
	Ssl3 *ssl;
public:
	/**
	 * Creates a new object for reading from a SSL connection.
	 * @param ssl the used Ssl3 to read from
	 */
	SslInputStream(Ssl3 *ssl_) :
			ssl(ssl_) {
	}

	/**
	 * Returns the number of bytes that can be read from this input stream without blocking.
	 * @return the number of bytes that can be read from this input stream without
	 * blocking.
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	int available() {
		if (!ssl->isConnected())
			return -1;
		return ssl->available();
	}

	/**
	 * Reads one byte from input stream with blocking.
	 * @return the value of the read byte or -1 on EOS
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	int read() {
		if (!ssl->isConnected())
			return -1;
		return ssl->read();
	}

	/**
	 * Reads into the given byte array from input stream with blocking until some data is read.
	 * @param b the buffer into which the data is read.
	 * @return the count of read data.
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	int read(void *buffer, int len) {
		if (!ssl->isConnected())
			return -1;
		bytez x(buffer, len);
		int r = ssl->read(x);
		return r;
	}

	/**
	 * Closes this input stream and releases any system resources associated with the stream.
	 * @throws java.io.IOException throws an IOException if an I/O Error occurs.
	 */
	int close() {
//    ssl.close();
		return 0;
	}
};

io::InputStream* Ssl3::getInputStream() {
	if (!myIn)
		myIn = new SslInputStream(this);
	return myIn;
}

void Ssl3::enableEncryption() {
	logme(L_DEBUG, "enable encryption");
	// enable read encryption
	readnum = 0;
	rhashBuffer.setSize(readHash->len());
}

void Ssl3::close() {
	is->close();
	connected = false;
}

const uint8_t * Ssl3::lookupCipher(char const * cname) {
	for (int i = 0; CIPHERSUITENAMES[i]; ++i) {
		if (0 == strcmp(cname, CIPHERSUITENAMES[i]))
			return CIPHERSUITES[i];
	}
	return 0;
}

bool Ssl3::setCiphers(char const * ciphers) {
	if (ciphers) {
		mstl::vector<const uint8_t*> cs;
		for (char const * p = ciphers;p;) {
			char const * q = strchr(p, ':');
			if (!q) q = strchr(p, ',');
			char const * next;
			if (!q) {
				q = p + strlen(p);
				next = 0;
			} else {
				next = q + 1;
			}

			int len = q - p;
			for (int i = 0; CIPHERSUITENAMES[i]; ++i) {
				if (0 == strncmp(p, CIPHERSUITENAMES[i], len)) {
					cs.push_back(CIPHERSUITES[i]);
					break;
				}
			}

			p = next;
		}

		if (cs.size() > 0) {
			cs.push_back(0);
			setCipherSuites(cs.begin());
			return true;
		}
	}
	return false;
}

uint8_t Ssl3::eekPriv[32];
uint8_t Ssl3::eekPub[32];

extern "C" void fe_new_key_pair(uint8_t *pk, uint8_t *sk);

void Ssl3::prepareEEK() {
	if (maxVersion >= 4 && *(uint32_t*)eekPriv == 0) {
		logme(L_DEBUG, "generating ed25519 key pair START");
		fe_new_key_pair(eekPub, eekPriv);
		logme(L_DEBUG, "generating ed25519 key pair STOP");
	}
}
