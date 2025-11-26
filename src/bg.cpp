/*
 * bebboget SSL/TLS client interface
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
 * Purpose: Provide Amiga applications with SSL/TLS client functions
 *          and utility routines for secure communication.
 *
 * Features:
 *  - Version reporting (bg_version)
 *  - Random data generation (bg_randfill)
 *  - SSL client lifecycle management (open, connect, send, recv, close)
 *  - Certificate verification and cipher configuration
 *  - SHA-256 hashing utility
 *
 * Curl backend usage:
 *  - The bg_* functions map directly to curl's vtls abstraction layer:
 *      * bg_ssl_open / bg_ssl_close -> session lifecycle
 *      * bg_ssl_connect            -> TLS handshake
 *      * bg_ssl_send / bg_ssl_recv -> encrypted I/O
 *      * bg_ssl_available          -> input stream availability
 *      * bg_ssl_verify             -> certificate chain validation
 *      * bg_ssl_set_ciphers        -> cipher suite configuration
 *  - This makes bebboget suitable as a drop-in backend for curl,
 *    requiring only a thin glue layer in curl's vtls module.
 *
 * Notes:
 *  - All functions are exposed with C linkage and __stdargs for Amiga ABI.
 *  - Caller is responsible for proper resource cleanup via bg_ssl_close().
 *  - Contributions must preserve author attribution and GPL licensing.
 * ----------------------------------------------------------------------
 */

#include "bebboget.h"
#include "rand.h"
#include "ssl3client.h"
#include "revision.h"
#include "certstuff.h"
#include "log.h"
#include "sha256.h"

/**
 * @brief Returns the version of the bebboget library.
 *
 * This method returns a constant string containing the version information in the format "bebboget [version]".
 * The actual version number is defined by the __V__ macro from the included revision header.
 *
 * Example: If __V__ is 3.5, this function will return "bebboget 3.5".
 *
 * @return char const* Pointer to a constant string containing the library version.
 */
extern "C" __stdargs char const * bg_version() {
    return "bebboget " __V__;
}

/**
 * @brief Fills a buffer with random data.
 *
 * This function fills the provided memory buffer with cryptographically secure random bytes.
 * The length parameter specifies how many bytes to generate.
 *
 * @param[in] to Pointer to the destination buffer where random bytes will be written.
 * @param[in] length Number of bytes to fill in the buffer.
 */
extern "C" __stdargs void bg_randfill(void * to, int length) {
    randfill(to, length);
}

/**
 * @brief Opens and prepares an SSL/TLS client instance with logging configuration.
 *
 * Creates a new Ssl3Client object, sets the log level to L_ERROR (or higher based on sloppy flag),
 * prepares the EEK (engine environment key), and initializes the client for use. This function should
 * be called before any connection or data transmission operations.
 *
 * The returned pointer must be passed to bg_ssl_close() when finished to clean up resources properly.
 *
 * @param[in] sloppy If true, enables additional debug logging during SSL handshake (default: false)
 * @return void* Pointer to the initialized SSL client instance, or nullptr if initialization fails.
 */
extern "C" __stdargs void * bg_ssl_open(int sloppy) {
    setLogLevel(L_ERROR);
    auto s = new Ssl3Client();
    if (s) {
        s->prepareEEK();
        s->setSloppy(sloppy);
    }
    return s;
}

/**
 * @brief Closes an SSL/TLS client instance and releases associated resources.
 *
 * Deletes the provided SSL client object, freeing all allocated memory and system resources.
 * This function should be called when finished with the SSL client to prevent resource leaks.
 *
 * The ssl parameter must not be nullptr as it is a pointer to an Ssl3Client object to delete.
 *
 * @param[in] ssl Pointer to the SSL client instance to close, must not be null.
 */
extern "C" __stdargs void bg_ssl_close(void * ssl) {
    if (ssl) {
        delete (Ssl3Client *) ssl;
    }
}

/**
 * @brief Establishes an SSL/TLS connection using a prepared client instance and socket descriptor.
 *
 * Initiates the SSL handshake process with the provided socket and remote host address. This function must
 * be called after bg_ssl_open() and before any data transmission operations (bg_ssl_send or bg_ssl_recv).
 *
 * The ssl parameter refers to an Ssl3Client object that has been prepared by bg_ssl_open(). It is expected
 * that this client instance already exists and is valid.
 *
 * @param[in] ssl Pointer to the SSL client instance. Must not be null.
 * @param[in] sock Socket descriptor for the underlying TCP connection.
 * @param[in] hostname Hostname of the server being connected to (not used in handshake, but passed as per
interface).
 * @return int Returns 0 on success, -1 on failure or error during handshake.
 */
extern "C" __stdargs int bg_ssl_connect(void *ssl, int sock, char const * hostname) {
    if (ssl) {
        auto ssl3 = (Ssl3Client *) ssl;
        return ssl3->connect(sock, hostname);
    }
    return -1;
}

/**
 * @brief Sends data over an established SSL/TLS connection.
 *
 * Writes the provided buffer of bytes to the SSL output stream. This function should only be used after a
 * successful call to bg_ssl_connect().
 *
 * The ssl parameter refers to an Ssl3Client object that has been connected (bg_ssl_connect() was called).
 * It is expected that this client instance already exists and is valid.
 *
 * @param[in] ssl Pointer to the SSL client instance. Must not be null.
 * @param[in] data Buffer containing the data to send.
 * @param[in] len Length of the data buffer in bytes.
 * @return int Returns number of bytes sent on success, -1 on error or if connection is closed.
 */
extern "C" __stdargs int bg_ssl_send(void *ssl, char const * data, int len) {
    if (ssl) {
        auto ssl3 = (Ssl3Client *) ssl;
        return ssl3->getOutputStream()->write(data, len);
    }
    return -1;
}

/**
 * @brief Receives data from an SSL/TLS connection.
 *
 * Reads available bytes from the SSL input stream into the provided buffer. This function should be called
 * periodically after a successful call to bg_ssl_connect() and when there is expected incoming data.
 *
 * The ssl parameter refers to an Ssl3Client object that has been connected (bg_ssl_connect() was called).
 * It is expected that this client instance already exists and is valid.
 *
 * @param[in] ssl Pointer to the SSL client instance. Must not be null.
 * @param[out] data Buffer where received data will be stored.
 * @param[in] len Size of the buffer in bytes.
 * @return int Returns number of bytes read on success, -1 on error or if no data is available.
 */
extern "C" __stdargs int bg_ssl_recv(void *ssl, char * data, int len) {
    if (ssl) {
        auto ssl3 = (Ssl3Client *) ssl;
        return ssl3->getInputStream()->read(data, len);
    }
    return -1;
}

/**
 * @brief Checks the number of bytes available in the SSL/TLS input stream.
 *
 * Returns the number of bytes available for reading from the SSL input stream if a valid connection exists,
 * otherwise returns 0 or appropriate error code based on implementation.
 *
 * This function should be used to determine how many bytes are available before attempting to receive data.
 * It is recommended to call this periodically after establishing a connection (bg_ssl_connect()).
 *
 * @param[in] ssl Pointer to the SSL client instance. Must not be null and must have been successfully connected.
 */
extern "C" __stdargs int bg_ssl_available(void *ssl) {
    if (ssl) {
        auto ssl3 = (Ssl3Client *) ssl;
        return ssl3->getInputStream()->available();
    }
    return -1;
}

/**
 * @brief Verifies the SSL certificate chain against a hostname.
 *
 * Checks if the server's SSL certificates are valid by verifying them against the provided hostname.
 * This function performs certificate verification and checks for potential issues in the handshake process.
 *
 * The ssl parameter must refer to an active SSL client instance (already connected).
 *
 * @param[in] ssl Pointer to the SSL client instance. Must not be null.
 * @param[in] hostname Hostname of the server being verified against.
 * @return int Returns 0 if certificates are valid, -1 otherwise or on error.
 */
extern "C" __stdargs int bg_ssl_verify(void *ssl, char const * hostname) {
    if (ssl) {
        auto ssl3 = (Ssl3Client *) ssl;
        return checkCertificates(hostname, ssl3->getCerts(), false);
    }
    return -1;
}

/**
 * @brief Sets the cipher list for an SSL/TLS client.
 *
 * Configures the SSL client to use a specific set of ciphers during the handshake process.
 * The function returns 0 if successful or if no change was needed, otherwise returns -1 on error.
 *
 * @param[in] ssl Pointer to the SSL client instance. Must not be null.
 * @param[in] ciphers String containing colon-/comma-separated cipher names (e.g., "ECDHE-ECDSA-CHACHA20-POLY1305")
 */
extern "C" __stdargs int bg_ssl_set_ciphers(void *ssl, char const * ciphers) {
    if (!ciphers)
        return 0;

    if (ssl) {
        auto ssl3 = (Ssl3Client *) ssl;
        if (ssl3->setCiphers(ciphers))
            return 0; // Success or no change
    }
    return -1;
}

/**
 * @brief Computes SHA-256 hash of data.
 *
 * Calculates the SHA-256 message digest for the given input data and stores it in the provided buffer.
 * Returns 0 on success, or -1 if any invalid parameters are passed (null pointers or negative length).
 *
 * The function uses the OpenSSL library to compute the hash. It assumes the input data is properly formatted
 * and handles memory management of the digest array - caller must provide valid storage for the 32-byte digest.
 *
 * @param[in] data Pointer to input data buffer, must not be null.
 * @param[in] len Length/size of the data in bytes (must be non-negative).
 * @param[out] digest Buffer to store the resulting SHA-256 hash (array of 32 integers or 32 characters)
 * @return int Returns 0 on success, -1 if any parameters are invalid.
 */
extern "C" __stdargs int bg_sha256sum(const void *data, int len, unsigned char *digest) {
	if (!data || len < 0 || !digest) {
		return -1;
	}

	SHA256 sha256;
	sha256.update(data, len);
	sha256.digest(digest);
	return 0; // Success
}
