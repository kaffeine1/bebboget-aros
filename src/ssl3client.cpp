/*
 * bebboget SSL 3.0 / TLS client implementation
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
 * Module: Ssl3Client
 *
 * Purpose:
 *  - Provide client-side implementation of SSL 3.0 / TLS handshake and record layer
 *  - Handle protocol negotiation, certificate validation, and session establishment
 *  - Integrate with bebboget's cryptographic library (RSA, ECDSA, AES, etc.)
 *
 * Notes:
 *  - SSL 3.0 is deprecated and insecure; TLS 1.2+ should be preferred
 *  - This implementation is maintained for compatibility and forensic analysis
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <time.h>

#include "ssl3.h"
#include "ssl3client.h"
#include "rand.h"
#include "md.h"
#include "md5.h"
#include "sha.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"

extern "C" void fe_new_key_pair(uint8_t *pk, uint8_t *sk);
extern "C" void fe_scalarmult_x25519(uint8_t *to, const uint8_t *scalar, const uint8_t *base);

#include "asn1.h"
#include "fastmath32.h"
#include "ecmath.h"
#include "pkcs6.h"
#include "secp256r1.h"
#include "log.h"

#define EC_X25519 1

#undef DEBUG
#ifdef DEBUG
#include <unhexlify.h>
#include <test.h>
#else
#include <test.h>
//#define _dump(a,b,c)
#endif

#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

static const uint8_t CLIENT_CHANGE_CIPHER_SPEC[6] = { 0x14, 0x03, 0x03, 00, 0x01, 0x01 };

int nomd(int no) {
	logme(L_ERROR, "no supported message digest %02lx", no);
	return SSL_ERR_NO_SUPPORTED_MESSAGE_DIGEST; //throw new IOException("not supported: " + b[0] + ", " + b[1]);
}

MessageDigest * makeMd(int no) {
	if (no == 2)
		return new SHA();
	if (no == 4)
		return new SHA256();
	if (no == 5)
		return new SHA384();
	if (no == 6)
		return new SHA512();

	return 0;
}

Ssl3Client::~Ssl3Client() {
	xero(preMasterSecret);
	xero(dhp);
	xero(dhg);
	xero(dhgy);
}

int Ssl3Client::newClientHello(char const *serverName) {
	writeBuffer.reserve(512);
	uint8_t * b = writeBuffer.begin();

	int off = 9;
	b[off++] = 3;
	b[off++] = maxVersion >= 3 ? 3 : maxVersion;
	off = addClientRandom(b, off);
	off = addSessionId(b, off);
	off = addCipherTypes(b, off);
	off = addCompression(b, off);

	// room for the extension length
	int extPos = off;
	off += 2;

	off = addServerNameExtension(b, off, serverName);
//    	off = addEcPointFormats(b, off);
	off = addSupportedGroups(b, off);	//mandatory
//    	off = addSessionTicket(b, off);
//    	off = addEncryptThenMac(b, off);
//    	off = addExtendedMasterSecret(b, off);
	off = addSignatureAlgorithms(b, off);	// mandatory
	off = addSupportedVersions(b, off);
//    	addPskExchangeModes(bos);
	if (maxVersion >= 4)
		off = addKeyShare(b, off);				// mandatory

	writeBuffer.setSize(off);

	int extLen = off - extPos - 2;
	b[extPos  ] = (uint8_t)(extLen >> 8);
	b[extPos+1] = (uint8_t)(extLen);

	addHandshakeHeader(1, b + 5, off - 9);
	addMessageHeader(22, b + 0, off - 5);

#ifdef DEBUG
	printf("%ld == %ld\n", off, writeBuffer.size());
#endif
	return off;
}

int Ssl3Client::addKeyShare(uint8_t * b, int off) {

	b[off++] = 0;
	b[off++] = 0x33;

	b[off++] = 0;
	b[off++] = 0x26;

	b[off++] = 0;
	b[off++] = 0x24;

	b[off++] = 0;
	b[off++] = 0x1d; // x25519

	b[off++] = 0;
	b[off++] = 0x20;

	hasEekPriv = true;
	memcpy(b + off, eekPub, sizeof(eekPub));
	off += 32;

	versionMinor = 1;
	return off;
}

int Ssl3Client::addSupportedVersions(uint8_t * b, int off) {
	static const uint8_t supportedVersions[] = {
			3, 4,
			3, 3,
	};

	if (maxVersion < 3)
		return off;

	const uint8_t * sv = supportedVersions;
	int len = sizeof(supportedVersions);

	if (maxVersion == 3) {
		sv += 2;
		len -= 2;
	}

	b[off++] = 0;
	b[off++] = 43;

	++len;
	b[off++] = len >> 8;
	b[off++] = len;

	b[off++] = --len;
	memcpy(b + off, sv, len);
	off += len;

	return off;
}

int Ssl3Client::addSignatureAlgorithms(uint8_t * b, int off) {
	static const uint8_t signatureAlgs[] = {
			4, 3,	// ecdsa_sha256
				5, 3,	// ecdsa_sha384
//				6, 3,	// ecdsa_sha512
//				8, 7,	// ed25519
//				8, 8,	// ed448
//				8, 9,
//				8, 0xa,
//				8, 0xb,
			8, 4,	// rsa_pss_rsae_sha256
			8, 5,	// rsa_pss_rsae_sha384
			8, 6,	// rsa_pss_rsae_sha512
			4, 1,	// rsa_pkcs1_sha256
			5, 1,	// rsa_pkcs1_sha384
			6, 1,	// rsa_pkcs1_sha512
//				3, 3,
//				3, 1,	// rsa_pkcs1_sha224
			2, 1,	// rsa_pkcs1_sha1
	};

	b[off++] = 0;
	b[off++] = 13;

	int len = sizeof(signatureAlgs) + 2;
	b[off++] = len >> 8;
	b[off++] = len;

	len -= 2;
	b[off++] = len >> 8;
	b[off++] = len;

	memcpy(b + off, signatureAlgs, len);
	off += len;

	return off;
}

int Ssl3Client::addSupportedGroups(uint8_t * b, int off) {
	static const uint8_t supportedGroups[] = {
			0, 0x1d,	// x25519
			0, 0x17,	// secp251r1
			0, 0x18,	// secp384r1
//				0, 0x1e,
//			0, 0x19,
//				1, 0,
//				1, 1,
//				1, 2,
//				1, 3,
//				1, 4
	};

	b[off++] = 0;
	b[off++] = 10;

	int len = sizeof(supportedGroups) + 2;
	b[off++] = len >> 8;
	b[off++] = len;

	len -= 2;
	b[off++] = len >> 8;
	b[off++] = len;

	memcpy(b + off, supportedGroups, len);
	off += len;

	return off;
}

int Ssl3Client::addServerNameExtension(uint8_t * b, int off, char const * name) {
	if (name) {
		int len = strlen(name);

		b[off++] = 0;
		b[off++] = 0;

		len += 5;
		b[off++] = len >> 8;
		b[off++] = len;

		len -= 2;
		b[off++] = len >> 8;
		b[off++] = len;

		b[off++] = 0;
		len -= 3;
		b[off++] = len >> 8;
		b[off++] = len;
		memcpy(b + off, name, len);
		off += len;
	}
	return off;
}

int Ssl3Client::addCompression(uint8_t * b, int off) {
	b[off++] = 1;
	b[off++] = 0;
	return off;
}

int Ssl3Client::addCipherTypes(uint8_t * b, int off) {
    int cipherPos = off;
    off += 2;

    for (const uint8_t ** csp = ciphersuites; *csp; ++csp) {
    	const uint8_t * cs = *csp;
    	b[off++] = cs[0];
    	b[off++] = cs[1];
    }

 // add dummy for TLS extensions to supportSecureNegotiation
    b[off++] = 0;
    b[off++] = 0xff;

    int sz = off - cipherPos - 2;
    b[cipherPos++] = sz >> 8;
    b[cipherPos] = sz;

    return off;
}

int Ssl3Client::addSessionId(uint8_t * b, int off) {
	sessionId.setSize(32);
	randfill(sessionId.begin(), 32);

	b[off++] = 32;
	memcpy(b + off, sessionId.begin(), 32);
	return off + 32;
}

int Ssl3Client::addClientRandom(uint8_t * b, int off) {
	clientRandom.setSize(32);
	randfill(clientRandom.begin(), 32);
	memcpy(b + off, clientRandom.begin(), 32);
	return off + 32;
}

int Ssl3Client::parseServerHello3() {
	uint8_t *b = innerReadBuffer.begin();
	int off = 0;
	int vh = b[off++];
	versionMinor = b[off++];
#ifdef DEBUG
	printf("minor version %ld\n", versionMinor);
#endif

	if (vh != 3 || versionMinor > maxVersion || versionMinor < minVersion) {
		logme(L_ERROR, "version %ld not in range; %ld - %ld", versionMinor, minVersion, maxVersion);
		return SSL_ERR_UNSUPPORTED_VERSION;
	}

	css[0] = 20;
	css[1] = 3;
	css[2] = versionMinor;
	css[3] = 0;
	css[4] = 1;
	css[5] = 1;

	serverRandom.setSize(32);
	memcpy(serverRandom.begin(), b + off, 32);
	off += 32; // 11 - 42 := Random

	int sl = b[off++] & 0xff; // session length
	sessionId.setSize(sl);
	if (sl)
		memcpy(sessionId.begin(), b + off, sl);
	off += sl; // 43 - 43+off := session id

	uint8_t ct0 = b[off++];
	uint8_t ct1 = b[off++];
	// we require NO compression
	if (b[off++] != 0) {
		logme(L_ERROR, "compression is not supported");
		return SSL_ERR_COMPRESSION_NOT_SUPPORTED;
	}

	// search the ciphertype
	const uint8_t **selected = ciphersuites;
	for (; *selected; ++selected) {
		if ((*selected)[0] == ct0 && (*selected)[1] == ct1)
			break;
	}
	if (!*selected) {
		logme(L_ERROR, "no matching ciphersuite");
		return SSL_ERR_NO_MATCHING_CIPHERSUITE;
	}
	masterSecret.setSize(0);

	// check for extensions as in TLS1.3
	if (off < innerReadBuffer.size()) {
		int totalExtLen = b[off++];
		totalExtLen = totalExtLen << 8 | (b[off++]);
		int end = off + totalExtLen;
		while (off < end) {
			int type = b[off++];
			type = (type << 8) | b[off++];
			int extLen = b[off++];
			extLen = (extLen << 8) | b[off++];
			switch (type) {
			case 0x2b: // version extension
				++off;
				versionMinor = b[off++];
				break;
			case 0x33: // early shared key
			{
				int ciph = b[off++];
				ciph = ciph << 8 | b[off++];
				int clen = b[off++];
				clen = clen << 8 | b[off++];
				if (ciph != 0x1D || clen != 32) {
					logme(L_ERROR, "unsupported early key method %08x len %ld", ciph, clen);
					return SSL_ERR_UNSUPPORTED_EARLY_KEY;
				}

				masterSecret.setSize(32);
				logme(L_DEBUG, "computing early master secret START");
				fe_scalarmult_x25519(masterSecret.begin(), eekPriv, b + off);
				logme(L_DEBUG, "computing early master secret STOP");
				off += clen;
			}
				break;
			default:
				off += extLen;
			}
		}
	}
	if (masterSecret.size() == 0) {
		hasEekPriv = false;
		if (versionMinor >= 4)
			versionMinor = 3;
	}

	return selected - ciphersuites;
}

int Ssl3Client::connect(int sock, char const *to) {
	socket = new net::Socket(sock);
	return connect(socket->getInputStream(), socket->getOutputStream(), to);
}

int Ssl3Client::connect(io::InputStream *_is, io::OutputStream *_os, char const *to) {
	setStreams(_is, _os);

	connected = false;
	collect = true;

	rhashBuffer.setSize(0);
	rpos = readBuffer.size();

	int len = newClientHello(to);
	logme(L_DEBUG, "sending CLIENT_HELLO");
	if (isLogLevel(L_TRACE))
		_dump("NEW_CLIENT_HELLO", writeBuffer.begin(), len);
	os->write(writeBuffer.begin(), len);
	os->flush();

	readnum = 0;
	writenum = 0;

	// receive the server hello
	if (hs_read(2) <= 0) {
		logme(L_ERROR, "no server hello received");
		return SSL_ERR_NO_SERVER_HELLO;
	}

	logme(L_DEBUG, "received SERVER_HELLO");
	if (isLogLevel(L_TRACE))
		_dump("SERVER_HELLO", innerReadBuffer.begin(), innerReadBuffer.size());

//    if (DEBUG.ON)
//        Misc.dump("serverHello", System.out, b);
	bytea oldSessionId; // = sessionId;

	cipherIndex = parseServerHello3();
	if (cipherIndex < 0) {
		logme(L_ERROR, "no matching ciphersuite");
		return SSL_ERR_NO_MATCHING_CIPHERSUITE;
	}

	startHandshakeHashes(cipherIndex);

	logme(L_DEBUG, "parsed SERVER_HELLO cipherIndex: %ld, hasEekPriv=%ld", cipherIndex, hasEekPriv);

	int r;
	if (hasEekPriv) {
		r = tls13Handshake(oldSessionId);
	} else {
		r = ssl3Handshake(oldSessionId);
	}

	collect = false; // disable handshake logging
	connected = r == 0;

	logme(L_DEBUG, "handshake done with %ld", r);

	return r;
}

int Ssl3Client::tls13Handshake(bytea &oldSessionId) {
	uint8_t *b;
	uint8_t onebyte[2];
	rawread(onebyte, 1, 20);
	if (onebyte[0] != 1) {
		logme(L_ERROR, "expected 0x01 got %02lx", onebyte[0]);
		return SSL_ERR_NO_TLS_HANDSHAKE_BYTE;
	}

	createTls13EarlyKeys(false);

	enableEncryption();

	// read as application data
	int r = 0;
	int verified = false;
	while (!r) {
		// need the hash without current message since the server used that to construct this message
		MessageDigest *m = hsSha->clone();
		rawread(head, 4, 22);
		if (innerRead() <= 0) {
			delete m;
			r = SSL_ERR_READ;
			break;
		}
		b = innerReadBuffer.begin();

		logme(L_DEBUG, "read handshake packet %ld", head[0]);
		if (isLogLevel(L_TRACE))
			_dump("handshake packet", innerReadBuffer.begin(), innerReadBuffer.size());
		switch (head[0]) {
		case 0x8: // server extensions
			break;
		case 0xb:
			certs = parseCertificate3(innerReadBuffer, 1);
			break;
		case 0xf:
			// ok
			if (sloppy) {
				r = 0;
				verified = true;
			}else {
				r = verifySignature(innerReadBuffer, 0, m);
				verified = r == 0;
			}
			break;
		case 0x14: {
			// ok
			if (!sloppy) {
				bytea verifyData = createTls13HandshakeFinished(m, serverSecret);
				r = memcmp(verifyData.begin(), innerReadBuffer.begin(), innerReadBuffer.size()) ? -1 : 0;
			}
			delete m;
			goto Outer;
		}
		}
		delete m;
	}

	Outer:
	if (!verified) {
		logme(L_ERROR, "certificate not verified");
		return r < 0 ? r : SSL_ERR_CERTIFICATE_NOT_VERIFIED;
	}

	MessageDigest *m = hsSha->clone();

	os->write(CLIENT_CHANGE_CIPHER_SPEC, 6);
	sendTls13ClientFinished();

	createTls13Keys(false, m);
	delete m;

	return r;
}

void Ssl3Client::sendTls13ClientFinished() {
	// calculate the hashes for the finished msg
	MessageDigest *m = hsSha->clone();
	bytea verify = createTls13HandshakeFinished(m, clientSecret);
	delete m;

	bytes(b, verify.size() + 4);

	b[0] = 20;
	b[1] = 0;
	b[2] = 0;
	b[3] = (uint8_t) (verify.size());
	memcpy(b.begin() + 4, verify.begin(), verify.size());

	updateHandshakeHashes(b.begin(), b.size());
	rawwrite(b.begin(), b.size(), 22);
}

bytea Ssl3Client::makeSignatureData13(MessageDigest * hsHash) {
	uint8_t hshash[hsHash->len()];
	hsHash->digest(hshash);

	// the data used to sign
	int vfylen = strlen(SERVER_VFY) + 1;
	bytea sigdata(64 + vfylen + hsHash->len());
	for (int i = 0; i < 64; ++i)
		sigdata[i] = ' ';
	memcpy(sigdata.begin() + 64, SERVER_VFY, vfylen);
	memcpy(sigdata.begin() + 64 + vfylen, hshash, hsHash->len());

	return sigdata;
}

bytea Ssl3Client::makeSignatureData12(uint8_t * b, int len) {
	bytea r(clientRandom.size() + serverRandom.size() + len);
	memcpy(r.begin(), clientRandom.begin(), clientRandom.size());
	memcpy(r.begin() + clientRandom.size(), serverRandom.begin(), serverRandom.size());
	memcpy(r.begin() + clientRandom.size() + serverRandom.size(), b, len);
	return r;
}

int Ssl3Client::verifySignature(bytez & ba, int off, MessageDigest *hsHash) {
	logme(L_DEBUG, "verify signature");

	uint8_t * b = ba.begin();
	MessageDigest *md = 0;

	bytea message = versionMinor == 4 ? makeSignatureData13(hsHash) : makeSignatureData12(b, off);
#ifdef DEBUG
	_dump("message", message.begin(), message.size());
#endif

	int kind = b[off++];
	if (kind == 8) {
		int mdno = b[off];
		md = makeMd(mdno);
		if (md == 0)
			return nomd(b[off]);

	//	if (DEBUG.ON)
	//		Misc.dump("rsa sig",  System.out, b, off, b.length - off);

		// length of signature
		unsigned len = (b[++off] & 0xff);
		len = (len << 8) | (b[++off] & 0xff);
		bytea signa(len);

		memcpy(signa.begin(), ++off + b, len);

		bytea &cert = certs[0];
		bytea e = Pkcs6::getX509Exponent(cert);
		bytea n = Pkcs6::getX509Modulo(cert);
		if (e.size() == 0 || n.size() == 0) {
			delete md;

			return SSL_ERR_NO_SUPPORTED_CERTIFICATE;
		}

		int emBits = n.size() * 8 - 1;
		signed char hi;
		if (n[0] == 0) {
			emBits -= 8;
			hi = n[1];
		} else
			hi = n[0];

		while ((hi & 0x80) == 0) {
			--emBits;
			hi <<= 1;
		}

	#ifdef DEBUG
		_dump("signa", signa.begin(), signa.size());
		_dump("n", n.begin(), n.size());
		_dump("e", e.begin(), e.size());
	#endif
		bytea signedContent = Pkcs6::doRSA(signa, n, e);
	#ifdef DEBUG
		_dump("signedContent", signedContent.begin(), signedContent.size());
	#endif
		int ok = sloppy || md->emsaPssVerify(message.begin(), message.size(), emBits, -1, signedContent.begin(), signedContent.size());

		delete md;

	//    if (!ok)
	//    	throw new IOException("certificate verify");
		return ok ? 0 : -22;
	}

	md = makeMd(kind);
	if (md == 0)
		return nomd(b[off]);

	++off;

	int len = b[off++] & 0xff;
	len = (len << 8) | (b[off++] & 0xff);

	if (len + off != ba.size())
		return SSL_ERR_CORRUPT_PACKET;

	uint8_t * sigData = b + off;

	bytea &cert = certs[0];
	bytea n = Pkcs6::getX509EcPub(cert);

	bytes (messageHash, md->len());
	md->update(message.begin(), message.size());
	md->digest(messageHash.begin());
	int ok = sloppy || SecpR1::verify(messageHash, sigData, ba.size() - off, n);
	if (!ok)
		return SSL_ERR_VERIFY_FAILED;

	return 0;
}

mstl::vector<bytea> Ssl3Client::parseCertificate3(bytea &b, int off) {
	logme(L_DEBUG, "parse certificates START");
	// certlistlen
	int cllen = ((b[off] & 0xff) << 16) | ((b[off + 1] & 0xff) << 8) | (b[off + 2] & 0xff);
	cllen += 3 - off;
	off += 3;
	mstl::vector<bytea> v;
	while (off < cllen) {
		// len of cert
		int clen;
		for(;;) {
			clen = ((b[off] & 0xff) << 16) | ((b[off + 1] & 0xff) << 8) | (b[off + 2] & 0xff);
			if (clen > 255) // some server send corrupt arrays with plenty zeroes...
				break;
			++off;
		}
		off += 3;

		if (off + clen > b.size())
			break;

		bytea a(clen);
		memcpy(a.begin(), b.begin() + off, clen);

		v.push_back(a);
		off += clen;
	}
	logme(L_DEBUG, "parsed %ld certificates STOP", v.size());
	return v;
}

int Ssl3Client::checkRSASignature(bytez &ba, int offset, MessageDigest *lastHsHash) {
	int len;
	int hash = 2;

	uint8_t *b = ba.begin();

//	if (DEBUG.ON)
//		Misc.dump("rsa sig",  System.out, b, offset, b.length - offset);

	if (versionMinor >= 3) {
		hash = b[offset];
		if (hash == 8) {
			return verifySignature(ba, offset, lastHsHash);
		}
		if (hash != 2 && hash != 4)
			return SSL_ERR_NO_SUPPORTED_ALGORITHM; // throw new IOException("expected SHA or SHA256");

		++offset;

		if (b[offset++] != 1)
			return SSL_ERR_NO_SUPPORTED_ALGORITHM; // throw new IOException("expected RSA signature");
	}

	if (sloppy)
		return 0;

	len = ((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff);
	bytes(bsigned, len);
	memcpy(bsigned.begin(), b + offset + 2, len);

	auto cert = certs[0];
	bytea e = Pkcs6::getX509Exponent(cert);
	bytea n = Pkcs6::getX509Modulo(cert);

	// get the signed content
	bytea signedContent = Pkcs6::doRSA(bsigned, n, e);

	// calculate our signature
	if (versionMinor >= 3)
		offset -= 2;

	bytea dhData = makeSignatureData12(b, offset);
	int keyLength = n.size() - (n[0] == 0 ? 1 : 0);
	bytea signedVerify;
	if (versionMinor >= 3) {
    	char const * hashName;
    	switch (hash) {
    	case 2: hashName = "SHA"; break;
    	case 5: hashName = "SHA384"; break;
    	case 6: hashName = "SHA512"; break;
    	default: hashName = "SHA256"; break;
    	}
		signedVerify = Pkcs6::prepareSignedContent(dhData, hashName, keyLength);
	} else {
		MD5 *md5 = new MD5;
		SHA *sha = new SHA;

		int md5len = md5->len();
		int shalen = sha->len();
		bytes(t, md5len + shalen);

		md5->update(dhData.begin(), dhData.size());
		md5->digest(t.begin());
		delete md5;

		sha->update(dhData.begin(), dhData.size());
		sha->digest(t.begin() + md5len);
		delete sha;

		signedVerify = Pkcs6::padSignedContent(t, keyLength, 2);
	}
	// fix for some broken servers!?
	signedVerify[1] = signedContent[1];
	if (signedContent.size() != signedVerify.size() || memcmp(signedContent.begin(), signedVerify.begin(), signedContent.size())) {
#ifdef DEBUG
    	_dump("content", signedContent.begin(), signedContent.size());
    	_dump("verify", signedVerify.begin(), signedVerify.size());
#endif
		return SSL_ERR_VERIFY_FAILED; //throw new IOException("dh key params signature mismatch");
	}

	return 0;
}

int Ssl3Client::readDheServerKey(bytea &ba, MessageDigest *lastHsHash) {
	logme(L_DEBUG, "read DHE server key");

	uint8_t *b = ba.begin();
	int len = ((b[0] & 0xff) << 8) | (b[1] & 0xff);
	if (len + 4 > ba.size())
		return SSL_ERR_CORRUPT_PACKET;

	dhp.setSize(len);
	memcpy(dhp.begin(), b + 2, len);

	int offset = len + 2;

	len = ((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff);
	if (len + offset + 4 > ba.size())
		return SSL_ERR_CORRUPT_PACKET;

	dhg.setSize(len);
	memcpy(dhg.begin(), b + offset + 2, len);

	offset += len + 2;

	len = ((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff);
	if (len + offset + 2 > ba.size())
		return SSL_ERR_CORRUPT_PACKET;

	preMasterSecret.setSize(len);
	memcpy(preMasterSecret.begin(), b + offset + 2, len);

	offset += len + 2;

	return checkRSASignature(ba, offset, lastHsHash);
}

int Ssl3Client::readDhECServerKey(bytez &ba, MessageDigest *lastHsHash) {
	logme(L_DEBUG, "read DHEC server key");
	uint8_t *b = ba.begin();
	if (b[0] != 3)
		return SSL_ERR_CORRUPT_PACKET; //throw new IOException("expected named curve");
	int curve = ((b[1] & 0xff) << 8) | (b[2] & 0xff);
	int len = b[3] & 0xff;
	if (curve >= 0x17 && curve <= 0x19) {
		if (b[4] != 4)
			return SSL_ERR_NO_SUPPORTED_ALGORITHM; // throw new IOException("need uncompressed");
		--len;
		len >>= 1;
		dhg.setSize(len);
		dhgy.setSize(len);
		memcpy(dhg.begin(), b + 5, len);
		memcpy(dhgy.begin(), b + 5 + len, len);

		int r = checkRSASignature(ba, 5 + len + len, lastHsHash);
		if (r)
			return r;
	} else if (curve == 0x1D || curve == 0x1E) {
		// X25519 or X448
		dhg.setSize(len);
		memcpy(dhg.begin(), b + 4, len);
#ifdef DEBUG
		_dump("dhg", dhg.begin(), dhg.size());
#endif
		int r = checkRSASignature(ba, 4 + len, lastHsHash);
		if (r)
			return r;
	} else
		return SSL_ERR_NO_SUPPORTED_ALGORITHM; // throw new IOException("unsupported curve");
	return curve;
}

int Ssl3Client::newEmptyClientCerts() {
	writeBuffer.setSize(12);
	uint8_t *w = writeBuffer.begin();
	w[9] = 0;
	w[10] = 0;
	w[11] = 0;
	addHandshakeHeader(11, w + 5, 3);
	addMessageHeader(22, w, 7);
	return 12;
}

int Ssl3Client::newClientKeyExchange3DhE() {
	logme(L_DEBUG, "DHE client key exchange");

	bytes(yr, dhp.size());
	randfill(yr.begin(), dhp.size());

#ifdef DEBUG
	_dump("preMasterSecret1", preMasterSecret.begin(), preMasterSecret.size());
#endif

	// update our preMasterSecret
	preMasterSecret = Pkcs6::doRSA(preMasterSecret, dhp, yr);

#ifdef DEBUG
	_dump("preMasterSecret2", preMasterSecret.begin(), preMasterSecret.size());
#endif
	// create the data for the server
	bytea y = Pkcs6::doRSA(dhg, dhp, yr);
#ifdef DEBUG
	_dump("y", y.begin(), y.size());
#endif

	int dlen = y.size() + 2;
	writeBuffer.setSize(dlen + 9);

	uint8_t *b = writeBuffer.begin();
	b[9] = (uint8_t) (y.size() >> 8);
	b[10] = (uint8_t) y.size();
	memcpy(b + 11, y.begin(), y.size());

	addHandshakeHeader(16, b + 5, dlen);
	addMessageHeader(22, b, dlen + 4);

	return dlen + 9;
}

int Ssl3Client::newClientKeyExchange3DHeC(int curve) {
	logme(L_DEBUG, "DHEC client key exchange");
	// create the premaster secret
	int dlen;
	uint8_t *b = writeBuffer.begin();
	if (curve == 0x1d) { // X22519

		bytes(clientPrivateKey, 32);

		b[9] = (uint8_t) 32;
		fe_new_key_pair(b + 10, clientPrivateKey.begin());
#ifdef FAKERAND
		unhexlify(clientPrivateKey.begin(),
			"00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F"
			"10 11 12 13 14 15 16 17  18 19 1A 1B 1C 1D 1E 5F");

		unhexlify(b + 10,
"8F 40 C5 AD B6 8F 25 62  4A E5 B2 14 EA 76 7A 6E"
"C9 4D 82 9D 3D 7B 5E 1A  D1 BA 6F 3E 21 38 28 5F");
#endif
		preMasterSecret.setSize(32);
		fe_scalarmult_x25519(preMasterSecret.begin(), clientPrivateKey.begin(), dhg.begin());
#ifdef DEBUG
_dump("dhg", dhg.begin(), 32);
_dump("clientPrivateKey", clientPrivateKey.begin(), 32);
_dump("preMasterSecret", preMasterSecret.begin(), 32);
#endif
#ifdef FAKERAND

		unhexlify(preMasterSecret.begin(),
"DF 6B AF 6F 6A 43 B9 74  4F C5 EF 9D EA 11 22 78"
"2F 9F 69 6D C4 A0 D1 5C  03 C1 78 7E E6 D1 5E 64");
#endif

		dlen = 33;
	} else if (curve == 0x1e) { // X448
		bytes(clientPrivateKey, 56);
		randfill(clientPrivateKey.begin(), 56);
		preMasterSecret = ECMath::x448(clientPrivateKey.begin(), dhg.begin());

		b[9] = (uint8_t) 56;
		ECMath::x448Pub(b + 10, clientPrivateKey.begin());
		dlen = 57;
	} else {
		bytea clientPrivateKey = ECMath::genPrivateKey(curve);
		preMasterSecret = ECMath::multX(curve, this->dhg, this->dhgy, clientPrivateKey);
		int ylen = ECMath::byteLength(curve);
		int osize = preMasterSecret.size();
		if (osize < ylen) {
			int delta = ylen - osize;
			preMasterSecret.setSize(ylen);
			memmove(preMasterSecret.begin() + delta, preMasterSecret.begin(), osize);
			while (delta > 0)
				preMasterSecret[--delta] = 0;
		}

		// create the pubkey for the server
		bytea pubx, puby;
		ECMath::pub(pubx, puby, curve, clientPrivateKey);
//		if (DEBUG.EC) {
//			Misc.dump("pubX", System.out, pub[0], 0, pub[0].length);
//		}

		dlen = 2 * ylen + 2;
		writeBuffer.setSize(dlen + 9);

		b[9] = (uint8_t) (1 + ylen * 2);
		b[10] = 4; // uncompressed

		memcpy(b + 11, pubx.begin(), ylen);
		memcpy(b + 11 + ylen, puby.begin(), ylen);
	}

	addHandshakeHeader(16, b + 5, dlen);
	addMessageHeader(22, b, dlen + 4);

#ifdef DEBUG
	_dump("newClientKeyExchange3DHeC", b, dlen + 9);
#endif

	return dlen + 9;
}

int Ssl3Client::newClientKeyExchange3RSA(mstl::vector<bytea> &v) {
	if (v.size() == 0)
		return SSL_ERR_CORRUPT_PACKET; //throw new IOException("no certificate");

	logme(L_DEBUG, "RSA key exchange");

	auto cert = v[0];
	// get the public key from certificate
	bytea ba = Asn1::getSeq(cert, Asn1::PK_PATH, 0);
	bytea nb = Asn1::getSeq(ba, Asn1::MODULO_PATH, ba[0] == 0 ? 1 : 0);
	bytea eb = Asn1::getSeq(ba, Asn1::EXPONENT_PATH, ba[0] == 0 ? 1 : 0);

	// create the premaster secret
	preMasterSecret.setSize(48);
	randfill(preMasterSecret.begin() + 2, 46);
	preMasterSecret[0] = 3;
	preMasterSecret[1] = versionMinor; // version

	// encrypted the preMasterSecret
	int dlen = nb.size();
	if (nb[0] == 0)
		--dlen;
	bytes(encodedPMS, dlen);
	randfill(encodedPMS.begin(), dlen);
	unzero(encodedPMS.begin(), dlen);
	encodedPMS[0] = 0;
	encodedPMS[1] = 2;
	encodedPMS[dlen - 49] = 0;
	memcpy(encodedPMS.begin() + dlen - 48, preMasterSecret.begin(), 48);

	uinta mod = FastMath32::byte2Int(nb, 0);
	uinta z = FastMath32::byte2Int(encodedPMS, (mod.size() << 1) + 1);

	uinta r = FastMath32::oddModPow(z, eb, mod);
	bytea encryptedPMS = FastMath32::int2Byte(r, dlen);

//    if (DEBUG.ON) {
//        Misc.dump("encoded PMS", System.out, encodedPMS);
//        Misc.dump("public exponent", System.out, eb);
//        Misc.dump("public modulo", System.out, nb);
//        Misc.dump("encrypted PMS", System.out, encryptedPMS);
//    }

	dlen = encodedPMS.size() - encryptedPMS.size();
	writeBuffer.setSize(encodedPMS.size() + 11);

	int offset = versionMinor == 0 ? 9 : 11;

	uint8_t *b = writeBuffer.begin();
	if (dlen >= 0) {
		// to short - insert leading zeros
		int j = offset;
		for (int i = 0; i < dlen; ++i, ++j) {
			b[j] = 0;
		}
		memcpy(b + j, encryptedPMS.begin(), encryptedPMS.size());
	} else {
		// copy only the fitting part
		memcpy(b + offset, encryptedPMS.begin() - dlen, encodedPMS.size());
	}
	dlen = encodedPMS.size();

	if (versionMinor > 0) {
		b[9] = (uint8_t) (dlen >> 8);
		b[10] = (uint8_t) dlen;
		dlen += 2;
	}

	addHandshakeHeader(16, b + 5, dlen);
	addMessageHeader(22, b, dlen + 4);

	dlen += 9;

//    if (DEBUG.ON)
//        Misc.dump("clientKeyExchange", System.out, ba, 0, dlen);

	return dlen;
}

void Ssl3Client::calcMasterSecret() {
//	if (DEBUG.HANDSHAKEHASH) {
//	    Misc.dump("SHA256", System.out, hsSha.clone().digest());
//	}

//	// calulate the master secret
#ifdef DEBUG
		_dump("preMasterSecret", preMasterSecret.begin(), preMasterSecret.size());
		_dump("clientRandom", clientRandom.begin(), clientRandom.size());
		_dump("serverRandom", serverRandom.begin(), serverRandom.size());
#endif

	if (versionMinor != 0)
		masterSecret = PRF(48, preMasterSecret, "master secret", 13, clientRandom, serverRandom);
	else
		masterSecret = makeHashBytes(preMasterSecret, 48, clientRandom, serverRandom);
}

int Ssl3Client::ssl3Handshake(bytea &oldSessionId) {
	int len;
	int exchange = sessionId.size() == 0 || sessionId.size() != oldSessionId.size() || memcmp(sessionId.begin(), oldSessionId.begin(), sessionId.size());

#ifdef DEBUG
	printf("exchanging a new key: %ld\n", exchange);
#endif

	if (exchange) {
		// receive the certificate
		if (hs_read(11) <= 0)
			return SSL_ERR_READ;

		if (isLogLevel(L_TRACE))
			_dump("received certificates", innerReadBuffer.begin(), innerReadBuffer.size());

		certs = parseCertificate3(innerReadBuffer, 0);
#ifdef DEBUG
		printf("got %ld certificates\n", certs.size());
#endif

		MessageDigest *lastHsHash = hsSha->clone();

		// receive server done
		int rlen = rawread(head, 4, 22);
		if (4 != rlen) {
			delete lastHsHash;
			return SSL_ERR_READ; //throw new IOException("handshake");
		}

		// DHE_RSA
		int useDHE = ciphersuites[cipherIndex][5];
		int curve = 0;
		if (useDHE == 1 || useDHE == 7) {
			if (head[0] != 12) {
				delete lastHsHash;
				return SSL_ERR_NO_SUPPORTED_ALGORITHM; // throw new IOException("handshake");
			}

			if (innerRead() <= 0) {
				delete lastHsHash;
				return SSL_ERR_READ;
			}
			if (isLogLevel(L_TRACE))
				_dump("received DHE server key", innerReadBuffer.begin(), innerReadBuffer.size());


#ifdef DEBUG
	        	_dump("ServerKeyExchange", innerReadBuffer.begin(), innerReadBuffer.size());
#endif

			if (useDHE == 1)
				readDheServerKey(innerReadBuffer, lastHsHash);
			else {
				curve = readDhECServerKey(innerReadBuffer, lastHsHash);
				if (curve < 0)
					return curve;
			}

			delete lastHsHash;

			rlen = rawread(head, 4, 22);
			if (4 != rlen)
				return SSL_ERR_READ; //throw new IOException("handshake");
		}

		// check for additional client certificate request
		int sendCerts = false;
		if (head[0] == 13) {
			if (innerRead() <= 0)
				return SSL_ERR_READ;

			sendCerts = true;

			rlen = rawread(head, 4, 22);
			if (4 != rlen)
				return SSL_ERR_READ; //throw new IOException("corrupt header received");

			if (isLogLevel(L_TRACE))
				_dump("received client certificate request", head, 4);

		}

		if (head[0] != 14)
			return SSL_ERR_CORRUPT_PACKET + 300; //throw new IOException("expected server done");

		if (innerRead() < 0)
			return SSL_ERR_READ;

		logme(L_DEBUG, "received server done");

		// writeln("got server done");

		if (sendCerts) {
			// send a zero client certificate list
			len = newEmptyClientCerts();
			logme(L_DEBUG, "sending empty client certs");
			os->write(writeBuffer.begin(), len);
		}
		// now use the certificates
		if (useDHE == 1) {
			len = newClientKeyExchange3DhE();
		} else if (useDHE == 7) {
			len = newClientKeyExchange3DHeC(curve);
		} else {
			len = newClientKeyExchange3RSA(certs);
		}
		if (isLogLevel(L_TRACE))
			_dump("sending client done", writeBuffer.begin(), len);
		os->write(writeBuffer.begin(), len);
		calcMasterSecret();
	}
//	if (DEBUG.ON) {
//	    Misc.dump("masterSecret", System.out, masterSecret);
//	}

	// calculate the keys for client(=>false)
	createKeys(false);

	os->flush();

	if (exchange) {
		sendSslClientFinished();
		return serverFinished();
	}

	int r =	serverFinished();
	if (r)
		return r;
	sendSslClientFinished();
	return 0;
}

void Ssl3Client::sendSslClientFinished() {
	logme(L_DEBUG, "send client finished");

	os->write(css, 6);

	// calculate the hashes for the finished msg
	bytea ba = finishedHash("client finished", CLIENT);

#ifdef DEBUG
	_dump("ba", ba.begin(), ba.size());
#endif


	uint8_t *b = ba.begin();
	b[0] = 20;
	b[1] = 0;
	b[2] = 0;
	b[3] = (uint8_t) (ba.size() - 4);

	updateHandshakeHashes(b, ba.size());

	if (isLogLevel(L_TRACE))
		_dump("client finished", b, ba.size());
	rawwrite(b, ba.size(), 22);
	// writeln("sent client finished");
	os->flush();
}

int Ssl3Client::serverFinished() {

	bytea ba = finishedHash("server finished", SERVER);

	// get changecipherspec
	uint8_t onebyte[2] = {0};
	rawread(onebyte, 1, 20);
	if (onebyte[0] != 1)
		return SSL_ERR_CORRUPT_PACKET + 400; //throw new IOException("ChangeCipherSpec");

	// enable read encryption
	readnum = 0;
	rhashBuffer.setSize(readHash->len());

	// writeln("got change cipher spec");

	int hsLen = versionMinor != 0 ? 16 : 40;
	bytes(f, hsLen);
	// get finished
	if (hsLen != rawread(f.begin(), hsLen, 22))
		return SSL_ERR_CORRUPT_PACKET; // throw new IOException();

	logme(L_DEBUG, "got server finished");

	if (memcmp(f.begin() + 4, ba.begin() + 4, ba.size() - 4))
		return SSL_ERR_CORRUPT_PACKET; //throw new IOException("finished: MAC error");

	return 0;
}

char const * Ssl3Client::getSelectedCiphersuite() const {
	if (!connected || cipherIndex < 0)
		return 0;

	uint8_t const * cs = ciphersuites[cipherIndex];

	for (int i = 0;;++i) {
		uint8_t const * s = CIPHERSUITES[i];
		if (!s)
			break;
		if (0 == memcmp(s, cs, 6))
			return CIPHERSUITENAMES[i];
	}
	return 0;
}

char const * Ssl3Client::getProtocolVersion() const {
	if (!connected)
		return "";
	switch (versionMinor) {
	case 0: return "SSL3.0";
	case 1: return "TSL1.0";
	case 2: return "TSL1.1";
	case 3: return "TSL1.2";
	case 4: return "TSL1.3";
	}
	return "?";
}
