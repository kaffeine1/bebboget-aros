/*
 * bebboget PKCS#6 / X.509 certificate utilities
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
 * Purpose: Provide PKCS#6 and X.509 certificate parsing and verification
 *          utilities, including RSA signature handling.
 *
 * Features:
 *  - Extract EC public key, RSA exponent, and modulus from X.509 certs
 *  - Perform RSA signature verification
 *  - Prepare and pad signed content
 *  - Verify certificate chains
 *  - Access issuer and owner fields
 *  - Provide ASN.1 object identifiers for SHA algorithms
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __PKCS6_H__
#define __PKCS6_H__

#include <time.h>

#ifndef __BYTEARRAY_H__
#include <bytearray.h>
#endif

/// Holds parsed certificate information
struct CertificateInfo {
    char* issuer;
    char* owner;
    char* dns;
    time_t validFrom;
    time_t validTo;
    int readable;
    int validSignature;
    int installed;
    bytea const* cert;

    /// Construct CertificateInfo from raw certificate
    CertificateInfo(bytea const* cert_)
        : issuer(0), owner(0), dns(0),
          validFrom(0), validTo(0),
          readable(false), validSignature(false), installed(false),
          cert(cert_) {}
};

class Pkcs6 {
public:
    /// Extract EC public key from X.509 certificate
    static bytea getX509EcPub(bytez const& cert);

    /// Extract RSA exponent from X.509 certificate
    static bytea getX509Exponent(bytez const& cert);

    /// Extract RSA modulus from X.509 certificate
    static bytea getX509Modulo(bytez const& cert);

    /// Perform RSA operation (signature verification)
    static bytea doRSA(bytez const& signa, bytez const& n, bytez const& e);

    /// Prepare signed content with given hash algorithm name
    static bytea prepareSignedContent(bytez const& sign, char const* hasName, unsigned keyLength);

    /// Pad signed content according to key length and type
    static bytea padSignedContent(bytez const& signedContent, int keyLength, int type);

    /// Verify a set of certificates
    static void verifyCertificates(mstl::vector<CertificateInfo>& cis, int verify);

    /// Extract issuer field from certificate
    static bytea getCertificateIssuer(bytez const& cert);

    /// Extract owner field from certificate
    static bytea getCertificateOwner(bytez const& cert);

    /// ASN.1 object identifiers for SHA algorithms
    static bytea const objectAlgorithmSHA512;
    static bytea const objectAlgorithmSHA384;
    static bytea const objectAlgorithmSHA256;
    static bytea const objectAlgorithmSHA;
    static bytea const newSeq;
    static bytea const nul;
};

#endif // __PKCS6_H__
