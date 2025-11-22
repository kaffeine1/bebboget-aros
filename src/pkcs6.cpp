/*
 * bebboget PKCS#6 certificate utilities
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
 * Module: PKCS#6 / Certificate verification
 *
 * Purpose:
 *  - Extract RSA/ECDSA public key parameters (modulus, exponent, EC pubkey) from X.509 certs
 *  - Verify signatures using RSA or ECDSA (SecpR1 curves)
 *  - Parse certificate attributes (owner, issuer, DNS names, validity times)
 *  - Provide helper functions for ASN.1 parsing and signature padding
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 *  - This code assumes well-formed ASN.1 structures; malformed certs may cause parsing errors
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "asn1.h"
#include "pkcs6.h"
#include "fastmath32.h"
#include "md5.h"
#include "sha.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "secp256r1.h"
#include "log.h"

#undef DEBUG
//#define DEBUG
#ifdef DEBUG
#include <test.h>
#else
#define _dump(a,b,c)
#endif

#ifdef __AMIGA__
#include <amistdio.h>
#else
#include <stdio.h>
extern char* concat(const char *s0, ...);
#endif

static const uint8_t CERT_OID_PATH[] = { 0x90, 0x90, 0x90, 0x86, 0 };
static const uint8_t ISSUER_PATH[] = { 0x90, 0x90, 0x10, 0x10, 0 };
static const uint8_t TIME_PATH[] = { 0x90, 0x90, 0x10, 0x10, 0x10, 0 };
static const uint8_t OWNER_PATH[] = { 0x90, 0x90, 0x10, 0x10, 0x10, 0x10, 0 };
static const uint8_t CERTPK_PATH[] = { 0x90, 0x90, 0x10, 0x10, 0x10, 0x10, 0x90, 0x83, 0 };

static const uint8_t CERTSIGPATH_PATH[] = { 0x90, 0x10, 0x10, 0x83, 0 };
static const uint8_t CERTCONTENT_PATH[] = { 0x90, 0x10, 0 };

static const uint8_t SIGNATUREHASH_PATH[] = { 0x90, 0x84, 0 };

static const uint8_t ENCRYPTION_PATH[] = { 0x90, 0x90, 6, 0 };
static const uint8_t ENCRYPTION_PATH_CSR[] = { 0x90, 0x10, 0x90, 6, 0 };

static const uint8_t CSRPK_PATH[] = { 0x90, 0x90, 0x10, 0x90, 0x83, 0 };

bytea const Pkcs6::nul = Asn1::makeASN1(bytea(), 5);
bytea const Pkcs6::newSeq = Asn1::makeASN1(bytea(), 0x30);

bytea const Pkcs6::objectAlgorithmSHA512 = Asn1::string2Oid("2.16.840.1.101.3.4.2.3");
bytea const Pkcs6::objectAlgorithmSHA384 = Asn1::string2Oid("2.16.840.1.101.3.4.2.2");
bytea const Pkcs6::objectAlgorithmSHA256 = Asn1::string2Oid("2.16.840.1.101.3.4.2.1");
bytea const Pkcs6::objectAlgorithmSHA = Asn1::string2Oid("1.3.14.3.2.26");
bytea const objectAlgorithmEcdsaWithSHA = Asn1::string2Oid("1.2.840.10045.4.3"); // .1 -> SHA224, .2 -> SHA256, .3 ->SHA384, .4 -> SHA512

static const bytea id_at_commonName = Asn1::string2Oid("2.5.4.3");
static const bytea id_at_surName = Asn1::string2Oid("2.5.4.4");
static const bytea id_at_organizationName = Asn1::string2Oid("2.5.4.10");
static const bytea id_at_organizationalUnitName = Asn1::string2Oid("2.5.4.11");
static const bytea id_at_countryName = Asn1::string2Oid("2.5.4.6");
static const bytea id_at_localityName = Asn1::string2Oid("2.5.4.7");
static const bytea id_at_stateOrProvinceName = Asn1::string2Oid("2.5.4.8");
static const bytea id_at_streetAddress = Asn1::string2Oid("2.5.4.9");

static bytea const *ids[] = { &id_at_streetAddress, &id_at_stateOrProvinceName, &id_at_localityName, &id_at_countryName, &id_at_organizationalUnitName,
		&id_at_organizationName, &id_at_surName, &id_at_commonName, 0 };

static bytea id_at_dns = Asn1::string2Oid("2.5.29.17");

static bytea md5withRSAEncryption = Asn1::string2Oid("1.2.840.113549.1.1.4");
static bytea sha1withRSAEncryption = Asn1::string2Oid("1.2.840.113549.1.1.5");
static bytea sha256WithRSAEncryption = Asn1::string2Oid("1.2.840.113549.1.1.11");

bytea Pkcs6::getX509EcPub(bytez const &cert) {
	bytea b = Asn1::getSeq(cert, CERTPK_PATH, 0);
	if (b.size() == 0)
		b = Asn1::getSeq(cert, CSRPK_PATH, 0);
	return b;
}

bytea Pkcs6::getX509Exponent(bytez const &cert) {
	bytea b = Asn1::getSeq(cert, CERTPK_PATH, 0);
	if (b.size() == 0)
		b = Asn1::getSeq(cert, CSRPK_PATH, 0);

	if (b.size() == 0)
		return b;

	uint8_t p2[] = { 0x90, 0x02, 0x82, 0 };
	return Asn1::getSeq(b, p2, b[0] == 0 ? 1 : 0);
}

bytea Pkcs6::getX509Modulo(bytez const &cert) {
	// get the public modulo from certificate
	bytea b = Asn1::getSeq(cert, CERTPK_PATH, 0);
	if (b.size() == 0)
		b = Asn1::getSeq(cert, CSRPK_PATH, 0);

	if (b.size() == 0)
		return b;

	uint8_t p1[] = { 0x90, 0x82, 0 };
	return Asn1::getSeq(b, p1, b[0] == 0 ? 1 : 0);
}

bytea Pkcs6::doRSA(bytez const &z, bytez const &mod, bytez const &e) {
	logme(L_DEBUG, "doRSA %ld START", mod.size());
	int mlen = (mod.size() >> 2) + 1;
	uinta iz = FastMath32::byte2Int(z, mlen);
	uinta in = FastMath32::byte2Int(mod, mlen);

	uinta ir = FastMath32::oddModPow(iz, e, in);

	int nlen = mod.size();
	if (mod[0] == 0)
		--nlen;

	bytea b = FastMath32::int2Byte(ir, nlen);
	logme(L_DEBUG, "doRSA %ld STOP", mod.size());
	return b;
}

bytea Pkcs6::prepareSignedContent(bytez const &sign, char const *hashName, unsigned keyLength) {
	MessageDigest *md = 0;
	bytez const *hashOid;
	if (0 == strcmp("SHA256", hashName)) {
		md = new SHA256();
		hashOid = &objectAlgorithmSHA256;
	} else {
		md = new SHA();
		hashOid = &objectAlgorithmSHA;
	}
#ifdef DEBUG
	_dump("hashOid", hashOid->begin(), hashOid->size());
#endif
	bytea t1 = Asn1::addTo(newSeq, Asn1::makeASN1(*hashOid, 6)); // OID
#ifdef DEBUG
	_dump("t1", t1.begin(), t1.size());
#endif
	bytea mdx = Asn1::addTo(t1, nul); // 0

	// hash berechnen
	bytes(signature, md->len());
	md->update(sign.begin(), sign.size());
	md->digest(signature.begin());

	// daten für RSA padden
	bytea t = Asn1::addTo(newSeq, mdx);
	bytea signedContent = Asn1::addTo(t, Asn1::makeASN1(signature, 4));
#ifdef DEBUG
	_dump("signedContent", signedContent.begin(), signedContent.size());
#endif
	return padSignedContent(signedContent, keyLength, 1);
}

bytea Pkcs6::padSignedContent(bytez const &signedContent, int keyLength, int type) {
	bytea tt;
	tt.setSize(keyLength);
	uint8_t *t = tt.begin();
	t[0] = 0;
	t[1] = (uint8_t) type;

	for (int i = 2; i < tt.size() - signedContent.size(); ++i) {
		t[i] = (uint8_t) 0xff;
	}
	int off = tt.size() - signedContent.size() - 1;
	t[off++] = 0;
	memcpy(t + off, signedContent.begin(), signedContent.size());
	return tt;
}

static int equals(bytez const &a, bytez const &b) {
	return a.size() == b.size() && 0 == memcmp(a.begin(), b.begin(), a.size());
}

static bytea decodeRSA(bytea const &uu) {
	uint8_t const *u = uu.begin();
	int i = 0;
	while (i < uu.size() && u[i] == 0) {
		++i;
	}
	if (i == uu.size() || u[i] != 1)
		return bytea();
	++i;
	while (i < uu.size() && u[i] == 0xff) {
		++i;
	}
	if (i == uu.size() || u[i] != 0)
		return bytea();
	++i;

	int sz = uu.size() - i;
	bytea r(sz);
	memcpy(r.begin(), u + i, sz);
	return r;
}

bytea getValueFor(bytez const &data, bytez const &oid) {
	int len = data.size() - oid.size();
	for (int i = 0; i < len; ++i) {
		if (0 == memcmp(data.begin() + i, oid.begin(), oid.size())) {
			return Asn1::getData(data, i + oid.size());
		}
	}
	return 0;
}

static const uint8_t CERT_ATTR_PATH[] = { 0x90, 0x90, 0x10, 0x10, 0x10, 0x10, 0x10, 0x83, 0 };

char* readDns(bytea const &attrs) {
	bytea dns = getValueFor(attrs, id_at_dns);
//	_dump("dns", dns.begin(), dns.size());
	uint8_t const *end = dns.begin() + dns.size();
	char *sdns = 0;
	for (uint8_t const *p = dns.begin(); p < end; ++p) {
		if (*p == 0x82) {
			++p;
			int len = *p++;
			if (p + len <= end) {
				char *s = (char *)malloc(len + 1);
				strncpy(s, (char*) p, len);
				s[len] = 0;
				char *c = concat(s, " ", sdns, 0);
				free(sdns);
				sdns = c;
				free(s);
			}
		}
	}
	return sdns;
}

char* readOids(bytea const &block) {
	char *r = 0;
	_dump("block", block.begin(), block.size());
	for (bytea const **p = ids; *p; ++p) {
		bytea v = getValueFor(block, **p);
		if (v.size()) {
			v.setSizeZ(v.size() + 1);
			char *t = concat((char*) v.begin(), r ? ", " : "", r, 0);
			free(r);
			r = t;
		}
	}
	return r;
}

void readTimes(CertificateInfo &ci, bytea const &times) {
    const uint8_t *p   = times.begin();
    const uint8_t *end = times.begin() + times.size();

    while (p < end) {
        if (*p != 0x17 && *p != 0x18) { // skip until UTCTime (0x17) or GeneralizedTime (0x18)
            ++p;
            continue;
        }

        uint8_t tag = *p++;
        unsigned l  = *p++;
        if (p + l > end) return;

        struct tm timeval = {0};
        if (tag == 0x17 && l == 13) {
            // UTCTime: YYMMDDhhmmssZ
            if (6 > sscanf((char*)p, "%2d%2d%2d%2d%2d%2d",
                           &timeval.tm_year, &timeval.tm_mon, &timeval.tm_mday,
                           &timeval.tm_hour, &timeval.tm_min, &timeval.tm_sec))
                return;
            timeval.tm_year += (timeval.tm_year < 50 ? 2000 : 1900) - 1900; // adjust century
        } else if (tag == 0x18 && l == 15) {
            // GeneralizedTime: YYYYMMDDhhmmssZ
            if (6 > sscanf((char*)p, "%4d%2d%2d%2d%2d%2d",
                           &timeval.tm_year, &timeval.tm_mon, &timeval.tm_mday,
                           &timeval.tm_hour, &timeval.tm_min, &timeval.tm_sec))
                return;
            timeval.tm_year -= 1900; // struct tm expects years since 1900
        } else {
            return; // unsupported format
        }

        timeval.tm_mon -= 1;
        time_t tval = mktime(&timeval);

        if (!ci.validFrom) {
            ci.validFrom = tval;
        } else {
            ci.validTo = tval;
            return; // stop after reading both times
        }

        p += l;
    }
}

void Pkcs6::verifyCertificates(mstl::vector<CertificateInfo> &cis, int verify) {
	if (cis.size() == 0)
		return;
	logme(L_DEBUG, "%s certificates START", verify ? "verifying" : "reading");

	bytea lastn; // used in RSA
	bytea laste; // used in RSA
	bytea lastec; // used in ECDHE
#ifdef DEBUG
	printf("nCerts: %ld\n", cis.size());
#endif
	for (int i = cis.size() - 1; i >= 0; --i) {
		CertificateInfo & ci = cis[i];
		bytea const *cert = ci.cert;
		bytea n, e, ec;
		do { //while false;

			bytea coid = Asn1::getSeq(*cert, CERT_OID_PATH, 0);
			if (coid.size() == 0)
				break;

			int isEcdsa = (coid.size() == objectAlgorithmEcdsaWithSHA.size() + 1)
					&& (0 == memcmp(coid.begin(), objectAlgorithmEcdsaWithSHA.begin(), MIN(coid.size(), objectAlgorithmEcdsaWithSHA.size())));
#ifdef DEBUG
			printf("isEcdsa: %ld\n", isEcdsa);
#endif
			bytea owner = getCertificateOwner(*cert);
			if (owner.size() == 0) // no owner
				break;

			ci.owner = readOids(owner);

			bytea attrs = Asn1::getSeq(*cert, CERT_ATTR_PATH, 0);
			if (attrs.size()) {
				ci.dns = readDns(attrs);
			}

			bytea issuer = getCertificateIssuer(*cert);
			if (issuer.size() == 0) // no issuer
				break;

			ci.issuer = readOids(issuer);

			bytea times = Asn1::getSeq(*cert, TIME_PATH, 0);
			if (times.size() == 0)
				break;

			readTimes(ci, times);

			ci.readable = true;
			ci.cert = cert;
			if (!verify)
				continue;

			bytea signature = Asn1::getSeq(*cert, CERTSIGPATH_PATH, 0);
			if (signature.size() == 0)
				break;

			ec = getX509EcPub(*cert);
			n = getX509Modulo(*cert);
			e = getX509Exponent(*cert);
// printf("%ld %ld %ld\n", ec.size(), n.size(), e.size());
			// self signed
			if (issuer.size() == owner.size() && 0 == memcmp(issuer.begin(), owner.begin(), issuer.size())) {
				lastn = n;
				laste = e;
				lastec = ec;
			}

			if (ci.validSignature)
				continue;

			bytea signedData = Asn1::getSeq(*cert, CERTCONTENT_PATH, 0);
			if (signedData.size() == 0)
				break;
			if (isEcdsa) {
				if (lastec.size() == 0)
					break;

				MessageDigest *md = 0;
				uint8_t *k = coid.begin() + objectAlgorithmEcdsaWithSHA.size();
				switch (*k) {
//				case 1: // SHA224
//					break;
					case 2:
						md = new SHA256();
						break;
					case 3:
						md = new SHA384();
						break;
					case 4:
						md = new SHA512();
						break;
				}
				if (md == 0)
					break;

				bytes(messageHash, md->len());
				md->update(signedData.begin(), signedData.size());
				md->digest(messageHash.begin());
#ifdef DEBUG
				_dump("messageHash", messageHash.begin(), messageHash.size());
				_dump("signature", signature.begin(), signature.size());
#endif
				// get r and s from signature
				uint8_t *ss = signature.begin();
				uint8_t *se = ss + signature.size();
				while (*ss != 0x02 && ss < se)
					++ss;

				if (*ss == 0x02) {
					int len = *++ss;
					bytez r(++ss, len);
					ss += len;
					if (*ss == 0x02) {
						len = *++ss;
						bytez s(++ss, len);
						ss += len;
#ifdef DEBUG
						_dump("r", r.begin(), r.size());
						_dump("s", s.begin(), s.size());
#endif
						if (ss == se) {
							ci.validSignature = SecpR1::verify(messageHash, r, s, lastec);
						}
					}
				}
			} else {

				if (lastn.size() == 0 || laste.size() == 0)
					break;

				bytea oid = Asn1::getSeq(signedData, ENCRYPTION_PATH, 0);
				if (oid.size() == 0) {
					oid = Asn1::getSeq(*cert, ENCRYPTION_PATH_CSR, 0);
					if (oid.size() == 0)
						break;
				}

				bytea oidData = Asn1::getData(oid);

				bytea decodedSignature = doRSA(signature, lastn, laste);
				if (decodedSignature.size() == 0)
					break;

				bytea encodedHash = decodeRSA(decodedSignature);
				if (encodedHash.size() == 0)
					break;

				bytea hash = Asn1::getSeq(encodedHash, SIGNATUREHASH_PATH, 0);
				if (hash.size() == 0)
					break;

				MessageDigest *md = 0;
				if (equals(oidData, sha1withRSAEncryption))
					md = new SHA();
				else if (equals(oidData, sha256WithRSAEncryption))
					md = new SHA256();
				else if (equals(oidData, md5withRSAEncryption))
					md = new MD5();
				if (md == 0)
					break;

				bytes(calcedHash, md->len());
				md->update(signedData.begin(), signedData.size());
				md->digest(calcedHash.begin());

				delete md;

				ci.validSignature = equals(hash, calcedHash);
			}
		} while (false);
//		printf("%ld: %s %s\n", ci.validSignature, ci.owner, ci.issuer);

		lastn = n;
		laste = e;
		lastec = ec;
	}
	logme(L_DEBUG, "%s certificates STOP", verify ? "verifying" : "reading");
}

bytea Pkcs6::getCertificateIssuer(bytez const &cert) {
	bytea b = Asn1::getSeq(cert, ISSUER_PATH, 0);
	return b;
}

bytea Pkcs6::getCertificateOwner(bytez const &cert) {
	bytea b = Asn1::getSeq(cert, OWNER_PATH, 0);
	return b;
}
