/*
 * bebboget installcerts utility
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
 * Module: installcerts
 *
 * Purpose:
 *  - Parse PEM-encoded X.509 certificates from a file
 *  - Verify certificates using PKCS#6 routines
 *  - Install verified certificates into the local trust store
 *  - Provide a simple CLI for Amiga and cross-platform builds
 *
 * Notes:
 *  - Input file may contain multiple concatenated certificates
 *  - Uses mimeDecode() to convert base64 PEM blocks to raw DER
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <stdlib.h>
#include <time.h>
#include <ministl/vector.h>
#include <revision.h>

#include <pkcs6.h>
#include <mime.h>
#include <certstuff.h>

#include <sys/stat.h>

#if defined(__AMIGA__)
#include <proto/dos.h>
#include <proto/exec.h>
#include <amistdio.h>

#else
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define __stdargs

#define gets(a,b) fgets(a, b, stdin)

char* concat(const char *s0, ...) {
	int sz = 1 + strlen(s0);
	va_list args;
	va_start(args, s0);
	for(;;) {
		char const *s = va_arg(args, char const*);
		if (!s)
			break;
		sz += strlen(s);
	}
	va_end(args);
	char * r = (char *)malloc(sz);
	if (r) {
		char * q = r;
		va_start(args, s0);
		while ((*q = *s0++)) {
			++q;
		}
		for(;;) {
			char const *s = va_arg(args, char const*);
			if (!s)
				break;
			while ((*q = *s++)) {
				++q;
			}
		}
		va_end(args);
	}
	return r;
}

#endif

#include <io/socket.h>
#include <ssl3client.h>

static char const * inFile;


static void printUsage() {
	puts(__VERSION);
	puts("USAGE: installcerts " __V__ " [options] <url>");
	puts("    -?            display this help");
	puts("");
	fflush(stdout);
}

static void parseParams(unsigned argc, const char **argv) {
	unsigned normal = 0;
	const char *arg = 0;

	if (argc == 1)
		goto usage;

	for (unsigned i = 1; i < argc; ++i) {
		arg = argv[i];
		if (normal == 0 && arg[0] == '-') {
			switch (arg[1]) {
			case '?':
				goto usage;
				/* no break */
			default:
				goto invalid;
			}
		}

		if (normal == 0) {
			inFile = arg;
		}

		++normal;
		continue;
	}

	if (normal == 1)
		return;

	usage: printUsage();
	exit(0);

	missing: printf("missing parameter for %s\n", arg);
	exit(10);

	invalid: printf("invalid option %s\n", arg);
	exit(10);
}

void parse(bytea & data) {
	char * p = (char *)data.begin();
	while (1) {
		char * begin = strstr(p, "-----BEGIN CERTIFICATE");
		if (!begin)
			break;

		begin = strchr(begin, '\n');
		if (!begin)
			break;

		char * end = strstr(p, "-----END CERTIFICATE");
		if (!end)
			break;
		*end++ = 0;
		int len = end - begin;
		bytea raw(len);
		int rawLen = mimeDecode(raw.begin(), begin, len);
		raw.setSize(rawLen);

		mstl::vector<CertificateInfo> cis;
		cis.push_back(CertificateInfo(&raw));
		Pkcs6::verifyCertificates(cis, false);
		CertificateInfo & ci = cis[0];

		printf("installing: %s\n", makeCertName(ci.owner));

		installCertificate(ci);

		p = end;
	}
}

extern "C" {
__stdargs
 int main(int argc, char const **argv) {
	parseParams(argc, argv);

	if (inFile) {
#ifdef __AMIGA__
		BPTR f = Open(inFile, MODE_OLDFILE);
		if (f) {
			Seek(f, 0, OFFSET_END);
			int sz = Seek(f, 0, OFFSET_BEGINNING);
			bytea data(sz + 1);
			data[sz] = 0;

			Read(f, data.begin(), sz);

			parse(data);

			Close(f);
#else
			FILE * f = fopen(inFile, "rb");
			if (f) {
				fseek(f, 0, SEEK_END);
				int sz = ftell(f);
				fseek(f, 0, SEEK_SET);
				bytea data(sz + 1);
				data[sz] = 0;

				fread(data.begin(), sz, 1, f);

				parse(data);

				fclose(f);
#endif
		} else {
			printf("can't open `%s` for reading\n", inFile);
		}
	}

	return 0;
}
}
