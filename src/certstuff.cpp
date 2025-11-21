/*
 * bebboget certificate management utilities
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
 * Purpose: Provide certificate installation, verification, and host name
 *          matching utilities for SSL/TLS connections.
 *
 * Features:
 *  - makeCertName(): sanitize and generate certificate file names
 *  - loadCertificate(): load certificate from filesystem
 *  - installCertificate(): write certificate to filesystem
 *  - isInstalledCertificate(): check if certificate is already installed
 *  - printCertInfo(): display certificate metadata
 *  - checkCertificates(): verify certificate chain, validity, and host name
 *
 * Notes:
 *  - Non-Amiga builds use ~/.config/bebboget as certificate directory
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <string.h>
#include <stdlib.h>

#include <pkcs6.h>
#include <log.h>

#if defined(__AMIGA__)
#include <proto/dos.h>
#include <proto/exec.h>
#include <amistdio.h>

/// Default certificate directory on Amiga
char const* certDir = "sys:Prefs/Env-Archive/certs";
#else
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

extern char* concat(const char* s0, ...);

/// Default certificate directory on POSIX systems
char const* certDir;

/// Initialize certificate directory under ~/.config/bebboget
static struct __ {
    __() {
        char* home = getenv("HOME");
        home = concat(home, "/.config/bebboget", NULL);
        for (char* p = strchr(home, '/'); p; p = strchr(p + 1, '/')) {
            *p = 0;
            mkdir(home, 0755);
            *p = '/';
        }
        certDir = home;
    }
} __;

#define __stdargs
#define gets(a,b) fgets(a, b, stdin)
#endif

/// Generate sanitized certificate file name
char* makeCertName(char const* in) {
    char* name = concat(certDir, "/", in, 0);
    for (char* p = name + strlen(certDir) + 1; *p; ++p) {
        if (!(*p >= '0' && *p <= '9') &&
            !(*p >= '@' && *p <= 'Z') &&
            !(*p >= 'a' && *p <= 'z') &&
            *p != '-')
            *p = '_';
    }
    char* r = concat(name, ".cer", 0);
    free(name);
    return r;
}

/// Load certificate from filesystem
bytea loadCertificate(char const* name) {
#if defined(__AMIGA__)
    BPTR f = Open(name, MODE_OLDFILE);
#else
    FILE* f = fopen(name, "rb");
#endif
    if (f) {
#if defined(__AMIGA__)
        Seek(f, 0, OFFSET_END);
        int size = Seek(f, 0, OFFSET_BEGINNING);
        bytea installed(size);
        Read(f, installed.begin(), installed.size());
        Close(f);
#else
        fseek(f, 0, SEEK_END);
        int size = ftell(f);
        fseek(f, 0, SEEK_SET);
        bytea installed(size);
        fread(installed.begin(), installed.size(), 1, f);
        fclose(f);
#endif
        return installed;
    }
    return 0;
}

/// Install certificate to filesystem
void installCertificate(CertificateInfo const& ci) {
    char* name = makeCertName(ci.owner);
#if defined(__AMIGA__)
    CreateDir(certDir);
    BPTR f = Open(name, MODE_NEWFILE);
#else
    mkdir(certDir, 0700);
    FILE* f = fopen(name, "wb");
#endif
    if (f) {
#if defined(__AMIGA__)
        Write(f, ci.cert->begin(), ci.cert->size());
        Close(f);
#else
        fwrite(ci.cert->begin(), ci.cert->size(), 1, f);
        fclose(f);
#endif
    }
    free(name);
}

/// Check if certificate is already installed
int isInstalledCertificate(CertificateInfo const& ci) {
    char* name = makeCertName(ci.owner);
#if defined(__AMIGA__)
    BPTR f = Open(name, MODE_OLDFILE);
#else
    FILE* f = fopen(name, "rb");
#endif
    if (f) {
        bytea installed(ci.cert->size());
#if defined(__AMIGA__)
        Read(f, installed.begin(), installed.size());
        Close(f);
#else
        fread(installed.begin(), installed.size(), 1, f);
        fclose(f);
#endif
        if (memcmp(installed.begin(), ci.cert->begin(), ci.cert->size()))
            f = 0;
    }
    free(name);
    return f != 0;
}

/// Print certificate metadata
void printCertInfo(CertificateInfo const& ci) {
    char* n;
    char* from = strdup(ctime(&ci.validFrom));
    if ((n = strchr(from, '\n'))) *n = 0;
    char* to = strdup(ctime(&ci.validTo));
    if ((n = strchr(to, '\n'))) *n = 0;

    printf("Owner     : %s\n", ci.owner);
    printf("Issuer    : %s\n", ci.issuer);
    printf("valid from: %s\n", from);
    printf("valid to  : %s\n", to);

    free(from);
    free(to);
}

/// Verify certificates and check host name
int checkCertificates(char const* host, mstl::vector<bytea> const& certs, bool installCertificates) {
    mstl::vector<CertificateInfo> cis;
    for (auto i = certs.begin(); i < certs.end(); ++i) {
        cis.push_back(CertificateInfo(i));
    }

    // Verify chain without enforcing trust
    Pkcs6::verifyCertificates(cis, false);
    for (auto ci = cis.begin(); ci < cis.end(); ++ci) {
        ci->installed = isInstalledCertificate(*ci);
        if (!ci->validSignature) {
            ci->validSignature = ci->installed;
        }
    }

    // Attempt to load root certificate if last is invalid
    bytea rootCert;
    auto last = *cis.rend();
    if (!last.validSignature) {
        char* fileName = makeCertName(last.issuer);
        rootCert = loadCertificate(fileName);
        logme(L_INFO, "attempt to load certificate for %s\n"
                      "issuer of %s\n"
                      "size=%ld : %s", last.issuer, last.owner, rootCert.size(), fileName);
        if (rootCert.size()) {
            mstl::vector<CertificateInfo> cis2;
            cis2.push_back(CertificateInfo(&rootCert));
            Pkcs6::verifyCertificates(cis2, false);
            CertificateInfo& ci = cis2[0];
            ci.installed = true;
            ci.validSignature = true;
            cis.push_back(ci);
        }
    }

    // Verify chain with trust enforcement
    Pkcs6::verifyCertificates(cis, true);

    time_t now = time(0);

    // Iterate over certificates
    for (auto ci = cis.begin(); ci < cis.end(); ++ci) {
        if (!ci->validSignature) {
            printf("\ncould not verify certificate for:\n");
            printCertInfo(*ci);
            printf("(a)bort, (i)nstall or (c)continue (a/i/c): "); fflush(stdout);

            char buff[256] = {0};
            gets(buff, 255);

            if (*buff == 'c' || *buff == 'C')
                ci->validSignature = true;
            if (*buff == 'i' || *buff == 'I') {
                ci->validSignature = true;
                installCertificate(*ci);
            }
        }
        if (ci->validSignature) {
            if (now < ci->validFrom || now > ci->validTo) {
                printf("the certificate is not valid today:\n");
                printCertInfo(*ci);
                printf("(a)bort or (c)continue (a/c): "); fflush(stdout);

                char buff[256];
                gets(buff, 256);
                if (*buff != 'c' && *buff != 'C')
                    ci->validSignature = false;
            }
            if (isLogLevel(L_INFO)) {
                printf("accepted certificate for:\n");
                printCertInfo(*ci);
            }
        }

        if (!ci->validSignature)
            return false;
        if (!ci->installed && installCertificates)
            installCertificate(*ci);
    }

    // now check the name against host
    auto& ci = cis[0];
    char* names = ci.dns;
    if (!names) {
        char* c = strchr(ci.owner, ' ');
        if (c)
            *c = 0;
        names = ci.owner;
    }

    int hlen = strlen(host);
    for (char const* pos = names; *pos;) {
        char const* found = strstr(pos, host);
        if (!found)
            break;
        if (found == names || found[-1] <= 32) { // check left boundary
            if (found[hlen] <= 32) { // check right boundary
                return true;
            }
        }
        pos += hlen;
    }

    // check for wildcard match
    char const* h = strchr(host, '.');
    if (h) {
        hlen = strlen(h);
        for (char const* pos = names; *pos;) {
            char const* found = strstr(pos, h);
            if (!found)
                break;
            if (found == names || found[-1] == '*') { // wildcard left
                if (found[hlen] <= 32) { // boundary right
                    return true;
                }
            }
            pos += hlen;
        }
    }

    printf("the certificate does not match the host name:\n"
           "names: %s\n"
           "host : %s\n", names, host);
    printf("(a)bort or (c)continue (a/c): "); fflush(stdout);

    char buff[256];
    gets(buff, 256);
    return (*buff == 'c' || *buff == 'C');
}
