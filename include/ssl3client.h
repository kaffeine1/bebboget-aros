/*
 * bebboget SSL3/TLS client interface
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
 * Purpose: Provide SSL3/TLS client implementation derived from Ssl3 base
 *          class, handling client-side handshake and key exchange.
 *
 * Features:
 *  - ClientHello construction with extensions (SNI, supported groups, etc.)
 *  - TLS 1.2 and TLS 1.3 handshake support
 *  - Certificate parsing and signature verification
 *  - Master secret calculation and key exchange methods
 *
 * Notes:
 *  - SSL3 is obsolete; TLS 1.2/1.3 should be preferred for secure use
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SSL3CLIENT_H__
#define __SSL3CLIENT_H__

#include <ssl3.h>

class Ssl3Client : public Ssl3 {
    int supportSessionTicket;   ///< whether session tickets are supported
    uint8_t css[6];             ///< selected cipher suite identifier
    int sloppy;                 ///< sloppy mode flag

public:
    /// Construct SSL3/TLS client with given cipher suites
    Ssl3Client(const uint8_t** ciphersuites = Ssl3::CIPHERSUITES)
        : Ssl3(ciphersuites), supportSessionTicket(false), sloppy(false) {}

    /// Destructor
    ~Ssl3Client();

    /// Connect using a socket descriptor
    int connect(int sock, char const* to);

    /// Connect using provided input/output streams
    int connect(io::InputStream* _in, io::OutputStream* _out, char const* to);

    /// Get selected cipher suite name
    char const* getSelectedCiphersuite() const;

    /// Get negotiated protocol version string
    char const* getProtocolVersion() const;

    /// Enable sloppy mode
    void setSloppy(int sl) { sloppy = sl; }

private:
    /// Build ClientHello message
    int newClientHello(char const* serverName);

    /// Add extensions and parameters to ClientHello
    int addClientRandom(uint8_t* b, int off);
    int addSessionId(uint8_t* b, int off);
    int addCipherTypes(uint8_t* b, int off);
    int addCompression(uint8_t* b, int off);
    int addServerNameExtension(uint8_t* b, int off, char const* name);
    int addSupportedGroups(uint8_t* b, int off);
    int addSignatureAlgorithms(uint8_t* b, int off);
    int addSupportedVersions(uint8_t* b, int off);
    int addKeyShare(uint8_t* b, int off);

    /// Parse ServerHello and perform handshake
    int parseServerHello3();
    int ssl3Handshake(bytea& oldSessionId);
    int tls13Handshake(bytea& oldSessionId);

    /// Verify server signature
    int verifySignature(bytez& b, int off, MessageDigest* hsHash);

    /// Construct signature data for TLS 1.3
    bytea makeSignatureData13(MessageDigest* hsHash);

    /// Construct signature data for TLS 1.2
    bytea makeSignatureData12(uint8_t* b, int off);

    /// Parse server certificate chain
    mstl::vector<bytea> parseCertificate3(bytea& b, int off);

    /// Send Finished messages
    void sendTls13ClientFinished();
    void sendSslClientFinished();

    /// Process server Finished message
    int serverFinished();

    /// Read server key exchange messages
    int readDheServerKey(bytea& b, MessageDigest* lastHsHash);
    int readDhECServerKey(bytez& ba, MessageDigest* lastHsHash);
    int checkRSASignature(bytez& ba, int offset, MessageDigest* lastHsHash);

    /// Client certificate and key exchange
    int newEmptyClientCerts();
    int newClientKeyExchange3DhE();
    int newClientKeyExchange3DHeC(int curve);
    int newClientKeyExchange3RSA(mstl::vector<bytea>& certs);

    /// Calculate master secret
    void calcMasterSecret();

    /// Key exchange buffers
    bytea preMasterSecret;
    bytea dhp;
    bytea dhg;
    bytea dhgy;
};

#endif // __SSL3CLIENT_H__
