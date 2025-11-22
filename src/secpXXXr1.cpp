/*
 * bebboget secp256r1/secp384r1 ECDSA verification
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
 * Module: secp256r1 / secp384r1 (NIST P-256, P-384)
 *
 * Purpose:
 *  - Verify ECDSA signatures over SHA-256 or SHA-384
 *  - Implement Jacobian point add/double and mixed multiplication
 *  - Support uncompressed public keys (0x04 || X || Y)
 *
 * Notes:
 *  - Curve parameter A is set to -3 (mod P) for these prime curves
 *  - Public key parsing expects uncompressed form; compressed keys are not supported here
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include <secp256r1.h>
#include <biginteger.h>
#include <log.h>
#include <test.h>

#ifdef __AMIGA__
#include <amistdio.h>
#else
#include <stdio.h>
#endif

BigInteger const BigInteger::ZERO(0);
BigInteger const BigInteger::ONE(1);
BigInteger const BigInteger::THREE(3);

static uint8_t __ONE[1] = { 1 };
static bytez ONE(__ONE, 1);

class JPoint {
	public:
		BigInteger x, y, z;

		JPoint(JPoint const &o) :
				x(o.x), y(o.y), z(o.z) {
		}

		JPoint& operator =(JPoint const &o) {
			x = o.x;
			y = o.y;
			z = o.z;
			return *this;
		}

		JPoint(BigInteger const &x_, BigInteger const &y_, BigInteger const &z_) :
				x(x_), y(y_), z(z_) {
		}

		JPoint(BigInteger &&x_, BigInteger &&y_, BigInteger &&z_) :
				x((BigInteger&&) x_), y((BigInteger&&) y_), z((BigInteger&&) z_) {
		}

		JPoint(BigInteger &&x_, BigInteger &&y_) :
				x((BigInteger&&) x_), y((BigInteger&&) y_), z(BigInteger::ONE) {
		}

		JPoint(bytez const &x_, bytez const &y_, bytez const &z_ = ONE) :
				x(1, x_.begin(), x_.size()), y(1, y_.begin(), y_.size()), z(1, z_.begin(), z_.size()) {
		}

		JPoint normalize(BigInteger const &p) const;
};

struct Curve {
		BigInteger P;
		BigInteger N;
		JPoint G;
		BigInteger A;

		Curve(BigInteger &&p, BigInteger &&n, BigInteger &&gx, BigInteger &&gy) :
				P((BigInteger&&) p), N((BigInteger&&) n), G((BigInteger&&) gx, (BigInteger&&) gy)
		, A((BigInteger &&) P.subtract(BigInteger::THREE)){
		}

		JPoint jacobianMultiply(JPoint const &p, BigInteger const &n);
		JPoint jacobianDouble(JPoint const &p);
		JPoint jacobianAdd(JPoint const &p, JPoint const &q);

		JPoint jacobianMulAdd(JPoint const &p1, BigInteger const &n1, JPoint const &p2, BigInteger const &n2);
};

static const uint8_t p256Bytes[] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t n256Bytes[] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7,
		0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };
static const uint8_t gx256Bytes[] = { 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
		0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96 };
static const uint8_t gy256Bytes[] = { 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b,
		0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5 };
static Curve SECP256R1((BigInteger&&) BigInteger(1, p256Bytes, sizeof(p256Bytes)), (BigInteger&&) BigInteger(1, n256Bytes, sizeof(n256Bytes)),
		(BigInteger&&) BigInteger(1, gx256Bytes, sizeof(gx256Bytes)), (BigInteger&&) BigInteger(1, gy256Bytes, sizeof(gy256Bytes)));

static const uint8_t p384Bytes[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0xff, 0xff };
static const uint8_t n384Bytes[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5,
		0x29, 0x73 };
static const uint8_t gx384Bytes[] = { 0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b,
		0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76,
		0x0a, 0xb7 };
static const uint8_t gy384Bytes[] = { 0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28,
		0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea,
		0x0e, 0x5f };
static Curve SECP384R1((BigInteger&&) BigInteger(1, p384Bytes, sizeof(p384Bytes)), (BigInteger&&) BigInteger(1, n384Bytes, sizeof(n384Bytes)),
		(BigInteger&&) BigInteger(1, gx384Bytes, sizeof(gx384Bytes)), (BigInteger&&) BigInteger(1, gy384Bytes, sizeof(gy384Bytes)));

JPoint JPoint::normalize(BigInteger const &P) const {
    // Compute modular inverse of z (Jacobian -> affine conversion)
    auto z0 = z.modInverse(P);

    // x_affine = (x * z^-2) mod P
    auto z2 = (z0 ^ 2) & P;
    auto x0 = (x * z2) & P;

    // y_affine = (y * z^-3) mod P
    auto z3 = (z2 * z0) & P;
    auto y0 = (y * z3) & P;

    // Return affine point (z=1)
    return JPoint((BigInteger&&)x0, (BigInteger&&)y0);
}

/**
 * q.z == 1
 */
JPoint Curve::jacobianAdd(JPoint const &p, JPoint const &q) {
    // Handle special cases: point at infinity
    if (p.y.equals(BigInteger::ZERO)) return q;
    if (q.y.equals(BigInteger::ZERO)) return p;

    // Compute U2 = q.x * p.z^2 mod P
    auto pz2 = (p.z ^ 2) & P;
    auto U2  = (q.x * pz2) & P;

    // Compute S2 = q.y * p.z^3 mod P
    auto pz3 = (p.z * pz2) & P;
    auto S2  = (q.y * pz3) & P;

    // If x-coordinates equal
    if (p.x.equals(U2)) {
        // If y differs -> point at infinity
        if (!p.y.equals(S2)) {
            return JPoint(BigInteger::ZERO, BigInteger::ZERO, BigInteger::ONE);
        }
        // Otherwise -> point doubling
        return jacobianDouble(p);
    }

    // H = U2 - p.x
    auto H = U2 - p.x;
    // R = S2 - p.y
    auto R = S2 - p.y;

    // Compute intermediate values
    auto H2   = (H ^ 2) & P;
    auto H3   = (H * H2) & P;
    auto U1H2 = (p.x * H2) & P;

    // nx = R^2 - H^3 - 2*U1H2
    auto nx = ((R ^ 2) - (H3 + U1H2 + U1H2)) & P;
    // ny = R*(U1H2 - nx) - p.y*H3
    auto ny = (R * (U1H2 - nx) - (p.y * H3)) & P;
    // nz = H * p.z
    auto nz = (H * p.z) & P;

    return JPoint((BigInteger&&) nx, (BigInteger&&) ny, (BigInteger&&) nz);
}

JPoint Curve::jacobianDouble(JPoint const &p) {
    // If y=0 -> point at infinity
    if (p.y.equals(BigInteger::ZERO)) {
        return JPoint(BigInteger::ZERO, BigInteger::ZERO, BigInteger::ZERO);
    }

    // z4 = (p.z^2)^2 mod P
    auto z4 = (((p.z ^ 2) & P) ^ 2) & P;

    // y^2
    auto ysq = (p.y ^ 2) & P;

    // S = 4 * p.x * y^2
    auto S = ((p.x << 2) * ysq) & P;

    // M = 3*p.x^2 + A*z^4
    auto px3 = p.x ^ 2;
    px3 = px3.add(px3).add(px3);
    auto M = (px3 + A * z4) & P;

    // nx = M^2 - 2*S
    auto nx = ((M ^ 2) - (S + S)) & P;

    // ny = M*(S - nx) - 8*y^4
    auto ysq3 = ((ysq ^ 2)) << 3;
    auto msnx = M * (S - nx);
    auto ny = (msnx - ysq3) & P;

    // nz = 2*y*z
    auto nz = ((p.y + p.y) * p.z) & P;

    return JPoint((BigInteger&&) nx, (BigInteger&&) ny, (BigInteger&&) nz);
}

JPoint Curve::jacobianMulAdd(JPoint const &p1, BigInteger const &n1,
                             JPoint const &p2, BigInteger const &n2) {
    // Convert scalars to byte arrays
    bytea scalar1 = n1.toByteArray();
    bytea scalar2 = n2.toByteArray();
    int bits = scalar1.size() * 8;

    // Precompute P1+P2
    JPoint p1p2 = jacobianAdd(p1, p2);
    p1p2 = p1p2.normalize(P);

    // Table of points for double-scalar multiplication
    JPoint const * pts[4] = { 0, &p1, &p2, &p1p2 };

    // Skip leading zero bytes in both scalars
    int index = 0;
    uint8_t *b1 = scalar1.begin();
    uint8_t *b2 = scalar2.begin();
    while (index < scalar1.size() && b1[index] == 0 && b2[index] == 0)
        ++index;
    index *= 8;

    // Initialize result as point at infinity
    JPoint r(BigInteger::ZERO, BigInteger::ZERO, BigInteger::ONE);

    // Double-and-add loop
    for (; index < bits; ++index) {
        r = jacobianDouble(r);

        // Extract bits from scalars
        int bit1 = (0x80 & (scalar1[index >> 3] << (index & 7))) >> 7;
        int bit2 = (0x80 & (scalar2[index >> 3] << (index & 7))) >> 6;

        // Add corresponding precomputed point
        JPoint const * p = pts[bit1 + bit2];
        if (p) r = jacobianAdd(r, *p);
    }

    return r;
}

int SecpR1::verify(bytez const &messageHash, uint8_t const *sigData, int len, bytez const &pubk) {
    logme(L_DEBUG, "verify %s START", messageHash.size() == 32 ? "secp256r1" : "secp384r1");

    // DER signature format: SEQUENCE { r INTEGER, s INTEGER }
    // sigData[0] = 0x30 (SEQUENCE), sigData[1] = total length
    int tlen = sigData[1] & 0xff;
    if (len != tlen + 2) return false;

    // Expect INTEGER tag for r
    if (sigData[2] != 0x02) return false;

    // Public key must be uncompressed form: optional 0x00, then 0x04
    int offset = (pubk[0] == 0x00 ? 1 : 0);
    if (pubk[offset] != 0x04) return false;

    // Extract r
    int rLen = sigData[3] & 0xff;
    bytes (r, rLen);
    memcpy(r.begin(), sigData + 4, rLen);
    int off = 4 + rLen;

    // Expect INTEGER tag for s
    if (sigData[off++] != 0x02) return false;

    // Extract s
    int sLen = sigData[off++] & 0xff;
    bytes (s, sLen);
    memcpy(s.begin(), sigData + off, sLen);

    // Delegate to main verify() with parsed r and s
    return verify(messageHash, r, s, pubk);
}


int SecpR1::verify(bytez const &messageHash, bytez const &r, bytez const &s, bytez const &pubk) {
    // Log start of verification, choose curve based on hash length
    logme(L_DEBUG, "verify %s START", messageHash.size() == 32 ? "secp256r1" : "secp384r1");

    Curve *c = nullptr;
    int coordLen = 0;
    switch (messageHash.size()) {
        case 32: // SHA-256 -> secp256r1
            c = &SECP256R1;
            coordLen = 32;
            break;
        case 48: // SHA-384 -> secp384r1
            c = &SECP384R1;
            coordLen = 48;
            break;
        default: // unsupported curve
            return false;
    }

    // Handle SSL/TLS public key encoding:
    // Sometimes ASN.1 OCTET STRING adds a leading 0x00 before the uncompressed point marker (0x04).
    int offset = (pubk[0] == 0x00 ? 1 : 0);

    // Must have uncompressed point marker (0x04)
    if (pubk[offset] != 0x04) return false;

    // Check total length: 0x04 + X + Y
    if (pubk.size() < offset + 1 + 2 * coordLen) return false;

    // Convert s to BigInteger and compute modular inverse (s^-1 mod N)
    BigInteger bs(1, s.begin(), s.size());
    BigInteger bsinv = bs.modInverse(c->N);

    // Convert message hash to BigInteger and multiply by s^-1 mod N
    BigInteger bm(1, messageHash.begin(), messageHash.size());
    BigInteger bmbi = bm.multiply(bsinv);
    BigInteger bminv = bmbi.mod(c->N);

    // Convert r to BigInteger and multiply by s^-1 mod N
    BigInteger br(1, r.begin(), r.size());
    BigInteger brinv = br.multiply(bsinv).mod(c->N);

    // Generator point G
    const JPoint &G = c->G;

    // Extract public key coordinates (X,Y) from buffer
    bytes (px, coordLen);
    memcpy(px.begin(), pubk.begin() + offset + 1, coordLen);
    bytes (py, coordLen);
    memcpy(py.begin(), pubk.begin() + offset + 1 + coordLen, coordLen);

    JPoint pubkey(px, py);

    // Compute w = bminv*G + brinv*pubkey in Jacobian coordinates
    JPoint w = c->jacobianMulAdd(G, bminv, pubkey, brinv);

    // Normalize back to affine coordinates
    w = w.normalize(c->P);

    // vx = w.x mod N
    BigInteger vx = w.x.mod(c->N);

    logme(L_DEBUG, "verify %s STOP", messageHash.size() == 32 ? "secp256r1" : "secp384r1");

    // Signature valid if vx == r
    return br.equals(vx);
}
