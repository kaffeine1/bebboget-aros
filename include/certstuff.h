/*
 * bebboget Certificate utilities
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
 * Purpose: Provide certificate handling utilities for SSL/TLS connections
 *          within the bebboget library.
 *
 * Features:
 *  - Create human-readable certificate names
 *  - Load certificates from storage
 *  - Install and check installed certificates
 *  - Print certificate information
 *  - Verify certificate chains against hostnames
 *
 * Notes:
 *  - Relies on PKCS#6 structures via pkcs6.h
 *  - Functions return standard types (int for status, bytea for data)
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __CERTSTUFF_H__
#define __CERTSTUFF_H__

#include "pkcs6.h"

/**
 * @brief Create a human-readable certificate name from input string.
 * @param[in] in Input string (e.g. subject or issuer).
 * @return Newly allocated string containing formatted certificate name.
 */
char* makeCertName(char const* in);

/**
 * @brief Load a certificate by name.
 * @param[in] name Certificate identifier or filename.
 * @return Certificate contents as bytea.
 */
bytea loadCertificate(char const* name);

/**
 * @brief Install a certificate into system storage.
 * @param[in] ci CertificateInfo structure containing certificate details.
 */
void installCertificate(CertificateInfo const& ci);

/**
 * @brief Check if a certificate is already installed.
 * @param[in] ci CertificateInfo structure containing certificate details.
 * @return Non-zero if installed, 0 otherwise.
 */
int isInstalledCertificate(CertificateInfo const& ci);

/**
 * @brief Print certificate information to output/log.
 * @param[in] ci CertificateInfo structure containing certificate details.
 */
void printCertInfo(CertificateInfo const& ci);

/**
 * @brief Verify a certificate chain against a hostname.
 * @param[in] host Hostname to verify against.
 * @param[in] certs Vector of certificate chains.
 * @param[in] installCertificates If true, install verified certificates.
 * @return 0 if verification succeeds, -1 otherwise.
 */
int checkCertificates(char const* host, mstl::vector<bytea> const& certs, bool installCertificates);

#endif // __CERTSTUFF_H__
