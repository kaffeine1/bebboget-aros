/*
 * bebboget SSL3/TLS interface
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
 * Purpose: Provide SSL3/TLS protocol handling, including handshake,
 *          cipher suite negotiation, and record layer operations.
 *
 * Features:
 *  - Support for multiple cipher suites (AES, RC4, DES, ChaCha20-Poly1305)
 *  - Handshake management and message hashing
 *  - TLS 1.3 key creation and PRF support
 *  - Stream abstraction via InputStream/OutputStream
 *
 * Notes:
 *  - SSL3 is obsolete; TLS 1.2/1.3 should be preferred for secure use
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SSL3_H__
#define __SSL3_H__

#include <stdint.h>
#include <io/stream.h>
#include <io/socket.h>
#include <bytearray.h>

class MessageDigest;
class BlockCipher;

/// Error codes for SSL/TLS operations
enum SslError {
    SSL_ERR_UNSUPPORTED_VERSION = -1000,
    SSL_ERR_UNSUPPORTED_EARLY_KEY,
    SSL_ERR_COMPRESSION_NOT_SUPPORTED,
    SSL_ERR_NO_MATCHING_CIPHERSUITE,
    SSL_ERR_NO_SERVER_HELLO,
    SSL_ERR_NO_TLS_HANDSHAKE_BYTE,
    SSL_ERR_CERTIFICATE_NOT_VERIFIED,
    SSL_ERR_VERIFY_FAILED,
    SSL_ERR_NO_SUPPORTED_MESSAGE_DIGEST,
    SSL_ERR_NO_SUPPORTED_CERTIFICATE,
    SSL_ERR_NO_SUPPORTED_ALGORITHM, // -990
    SSL_ERR_CORRUPT_PACKET,
    SSL_ERR_READ,	// -988
    SSL_ERR_ALERT,
};

/// Zero out a byte array
extern void xero(bytea& v);

class Ssl3 {
public:
    /// Supported block cipher identifiers
    enum { BC_RC4 = 0, BC_AES, BC_DES3, BC_DES, BC_AES_GCM, BC_CHACHA20_POLY1305 };

    // Cipher suite definitions (6-byte identifiers)
    static const uint8_t TLS_CHACHA20_POLY1305_SHA256[6];
    static const uint8_t TLS_AES_256_GCM_SHA384[6];
    static const uint8_t TLS_AES_128_GCM_SHA256[6];
    static const uint8_t TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384[6];
    static const uint8_t TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256[6];
    static const uint8_t TLS_DHE_RSA_WITH_AES_256_GCM_SHA384[6];
    static const uint8_t TLS_DHE_RSA_WITH_AES_128_GCM_SHA256[6];
    static const uint8_t TLS_RSA_WITH_AES_256_GCM_SHA384[6];
    static const uint8_t TLS_RSA_WITH_AES_128_GCM_SHA256[6];
    static const uint8_t TLS_DHE_RSA_WITH_AES_256_CBC_SHA256[6];
    static const uint8_t TLS_DHE_RSA_WITH_AES_256_CBC_SHA[6];
    static const uint8_t TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256[6];
    static const uint8_t TLS_DHE_RSA_WITH_AES_128_CBC_SHA256[6];
    static const uint8_t TLS_DHE_RSA_WITH_AES_128_CBC_SHA[6];
    static const uint8_t TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA[6];
    static const uint8_t TLS_RSA_WITH_AES_256_CBC_SHA256[6];
    static const uint8_t TLS_RSA_WITH_AES_128_CBC_SHA256[6];
    static const uint8_t TLS_RSA_WITH_AES_256_CBC_SHA[6];
    static const uint8_t TLS_RSA_WITH_AES_128_CBC_SHA[6];

    static const uint8_t TLS_RSA_WITH_3DES_EDE_CBC_SHA[6];
    static const uint8_t TLS_RSA_WITH_DES_CBC_SHA[6];
    static const uint8_t TLS_RSA_WITH_RC4_128_SHA[6];
    static const uint8_t TLS_RSA_WITH_RC4_128_MD5[6];
    static const uint8_t TLS_RSA_EXPORT_WITH_RC4_40_MD5[6];

    /// Construct SSL3/TLS handler with given cipher suites
    Ssl3(const uint8_t** ciphersuites_);
    virtual ~Ssl3();

    /// Access input/output streams
    io::InputStream* getInputStream();
    io::OutputStream* getOutputStream();

    /// Read/write operations
    int write(bytez& b);
    int read();
    int read(bytez& ba);
    int available();

    /// Version management
    inline void setMaxVersion(int max) { maxVersion = max; }
    inline void setMinVersion(int min) { minVersion = min; }
    inline int isConnected() const { return connected; }

    /// Cipher suite lookup
    static const uint8_t* CIPHERSUITES[];
    static const char* CIPHERSUITENAMES[];
    static const uint8_t* lookupCipher(char const* cname);

    bool setCiphers(char const* ciphers);
    void setCipherSuites(const uint8_t** ciphersuites_);

    /// Close connection
    void close();

    /// Access certificates
    inline mstl::vector<bytea> const& getCerts() const { return certs; }

    /// Prepare ephemeral keys
    void prepareEEK();

protected:
    static const char* SERVER_VFY;
    static const uint8_t SERVER[];
    static const uint8_t CLIENT[];
    static const uint8_t NULLBYTES[64];
    static const uint8_t SPACE32[];
    static const uint8_t ALERTCLOSE[];

    static uint8_t eekPriv[32];
    static uint8_t eekPub[32];

    io::InputStream* myIn;
    io::OutputStream* myOut;

    int collect;
    int connected;

    const uint8_t** ciphersuites;
    mstl::vector<bytea> certs;

    io::InputStream* is;
    io::OutputStream* os;
    net::Socket* socket;

    int cipherIndex;

    MessageDigest* md5;
    MessageDigest* sha;
    MessageDigest* prfMd;

    uint8_t head[4];
    uint8_t r5[5];

    bytea innerReadBuffer;
    bytea readBuffer;
    int rpos;
    int readBufferLength;

    bytea writeBuffer;
    int odd; ///< alignment for 68000

    bytea masterSecret;
    bytea clientRandom;
    bytea serverRandom;
    bytea sessionId;

    bytea readSecret;
    bytea writeSecret;

    MessageDigest* readHash;
    MessageDigest* writeHash;
    bytea rhashBuffer;

    MessageDigest* hsMd5;
    MessageDigest* hsSha;

    unsigned long long readnum, writenum;

    bytea pendingHandshake;

    BlockCipher* cryptRead;
    BlockCipher* cryptWrite;

    bytea readIV;
    bytea writeIV;

    uint16_t maxVersion;
    uint16_t minVersion;
    uint16_t versionMinor;

    uint8_t writeAad[13]; uint8_t align1[1];
    uint8_t readAad[13];  uint8_t align2[1];
    uint8_t writeNonce[12];
    uint8_t readNonce[12];
    int hasEekPriv;

    bytea serverSecret;
    bytea clientSecret;
    bytea handshakeSecret;

    /// Internal helpers
    void calcMessageHash(uint8_t* to, MessageDigest* md, bytea& secret,
                         unsigned long long seqNum, int typ,
                         uint8_t* b, unsigned long blength);
    int readFully(uint8_t* b, int length);
    int readahead();
    int rawread(uint8_t* b, int blen, int typ);
    int rawwrite(uint8_t* b, unsigned len, int typ);

    int innerRead();
    int hs_read(int msgType);

    int aeadDecrypt(int typ, unsigned len);
    int aeadEncrypt(uint8_t* b, unsigned blen, int typ);

    void setStreams(io::InputStream* _is, io::OutputStream* _os) { is = _is; os = _os; }
    void clear();

    void updateHandshakeHashes(uint8_t* b, unsigned length);
    void addHandshakeHeader(int msgType, uint8_t* b, unsigned length);
    void addMessageHeader(int packetType, uint8_t* b, unsigned length);

    void startHandshakeHashes(int selectedCipherSuite);

    void createTls13EarlyKeys(int isServer);
    bytea createTls13HandshakeFinished(MessageDigest* md, bytea const& secret);
    void createTls13Keys(int isServer, MessageDigest* lastHsHash);

    /// TLS PRF (Pseudo-Random Function) for key derivation
    bytea PRF(int length, bytez& secret, char const* id, int idLen,
              bytez& add1, bytez& add2);

    /// Helper to construct hash bytes for key derivation
    bytea makeHashBytes(bytez& x, int n, bytez& ra, bytez& input);

    /// Create session keys (pre-TLS 1.3)
    void createKeys(int isServer);

    /// Compute Finished message hash
    bytea finishedHash(char const* cs, uint8_t const* csData);

    /// Calculate handshake hash
    void calc_hs_hash(void* to, MessageDigest* md, int len, bytez& sender);

    /// Enable record layer encryption
    void enableEncryption();
};

#endif // __SSL3_H__
