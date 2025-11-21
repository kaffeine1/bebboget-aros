#ifndef __BEBBOGET_H__
#define __BEBBOGET_H__

// This macro ensures the function declarations are compatible with both C and C++ code
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __stdargs
#define __stdargs
#endif

/*
 * Function: bg_version()
 * --------------------
 * Returns a pointer to a string containing the library version number.
 * The caller must not modify or free this buffer as it is read-only.
 *
 * Parameters:
 *   None
 */
__stdargs const char * bg_version();

/*
 * Function: bg_randfill()
 * --------------------
 * Fills a memory region with random data using a secure random generator.
 *
 * Parameters:
 *   to     - Pointer to the memory buffer to fill (must be writable)
 *   length - Size of the buffer in bytes
 */
__stdargs void bg_randfill(void * to, int length);

/*
 * Function: bg_ssl_open()
 * --------------------
 * Initializes and returns a pointer to an SSL context/object.
 *
 * Parameters:
 *   sloppy - If true verifications is skipped.
 */
__stdargs void * bg_ssl_open(int sloppy);

/*
 * Function: bg_ssl_close()
 * --------------------
 * Frees the resources associated with an SSL object and closes the underlying connection.
 *
 * Parameters:
 *   ssl - Pointer to the SSL object to close
 */
__stdargs void bg_ssl_close(void * ssl);

/*
 * Function: bg_ssl_connect()
 * --------------------
 * Establishes a secure TLS/SSL connection using the provided socket and hostname for verification.
 *
 * Parameters:
 *   ssl      - Pointer to the SSL object (previously opened)
 *   sock     - Socket descriptor from which communication will occur
 *   hostname - Hostname used during SSL handshake for certificate validation
 */
__stdargs int bg_ssl_connect(void* ssl, int sock, char const * hostname);

/*
 * Function: bg_ssl_send()
 * --------------------
 * Sends data over an established SSL/TLS connection.
 *
 * Parameters:
 *   ssl  - Pointer to the SSL object (must be connected)
 *   data - Pointer to buffer containing data to send
 *   len  - Size of the data in bytes
 */
__stdargs int bg_ssl_send(void* ssl, char const * data, int len);

/*
 * Function: bg_ssl_recv()
 * --------------------
 * Receives data from an established SSL/TLS connection into a provided buffer.
 *
 * Parameters:
 *   ssl  - Pointer to the SSL object (must be connected)
 *   data - Pointer to buffer where received data will be stored
 *   len  - Size of the buffer in bytes; actual number of bytes read may be less or equal
 */
__stdargs int bg_ssl_recv(void* ssl, char * data, int len);

/*
 * Function: bg_ssl_available()
 * --------------------
 * Returns the number of bytes available for reading on an SSL/TLS connection.
 *
 * Parameters:
 *   ssl - Pointer to the SSL object (must be connected)
 */
__stdargs int bg_ssl_available(void* ssl);

/*
 * Function: bg_ssl_verify()
 * --------------------
 * Checks if the hostname matches the server's certificate during SSL handshake.
 * Returns non-zero if verification fails, zero otherwise.
 *
 * Parameters:
 *   ssl      - Pointer to the SSL object (must be connected)
 *   hostname - Hostname provided during connection for comparison
 */
__stdargs int bg_ssl_verify(void* ssl, char const * hostname);

/*
 * Function: bg_ssl_set_ciphers()
 * --------------------
 * Configures the cipher suite preferences for the SSL/TLS handshake.
 *
 * Parameters:
 *   ssl     - Pointer to the SSL object (must be opened but not necessarily connected)
 *   ciphers - String of preferred ciphers in OpenSSL format (e.g., "ECDHE-ECDSA-AES128-GCM-SHA256")
 */
__stdargs int bg_ssl_set_ciphers(void* ssl, char const * ciphers);

/*
 * Function: bg_sha256sum()
 * --------------------
 * Computes the SHA-256 hash of a given data buffer and returns it in binary form.
 *
 * Parameters:
 *   data    - Pointer to input data buffer
 *   len     - Size of input data in bytes
 *   digest  - Pointer to buffer (at least 32 bytes) where the resulting hash will be stored
 */
__stdargs int bg_sha256sum(const void *data, int len, unsigned char *digest);

#ifdef __cplusplus
}
#endif

#endif //__BEBBOGET_H__
