# bebboget

**Get HTTPS files from the internet on your Amiga — no dependencies.**

- **Author:** Stefan "Bebbo" Franke <s.franke@bebbosoft.de>  
- **Uploader:** s.franke@bebbosoft.de  
- **Upstream architecture:** m68k-amigaos  
- **AROS fork targets:** i386 `alt-abiv0`, x86_64 (mincrt), aarch64 (Raspberry Pi)  
- **Type:** comm/net  
- **Version:** 1.11
- **Required:** `bsdsocket.library` (e.g. AmiTCP)  
- **Replaces:** `amigaget`

---

## AROS port

This repository is a fork of bebboget by Stefan "Bebbo" Franke, based on
upstream 1.11 (commit `9b223f1` of https://franke.ms/git/bebbo/bebboget). The
AROS changes are Copyright (C) 2026 Michele Dipace
<michele.dipace@kaffeine.net>, GNU GPL v3 or later like the upstream code.

One source tree builds three AROS targets:

| Target | Makefile | Tested on |
| --- | --- | --- |
| i386 `alt-abiv0` (AROS One 32-bit) | `Makefile.aros` | AROS One i386 under QEMU |
| x86_64 `mincrt` (AROS One 64-bit) | `Makefile.aros-x86_64` | AROS One x86_64 under QEMU |
| aarch64 (AROS on the Raspberry Pi) | `Makefile.aros-aarch64` | Raspberry Pi 400; QEMU `raspi3b`, short transfers only |

Releases, one per target, are on the
[releases page](https://github.com/kaffeine1/bebboget-aros/releases). I
uploaded the same archives to Aminet (`comm/net`) and The AROS Archives
(`network/misc`).

What works: HTTPS downloads over TLS 1.2 and TLS 1.3 (ChaCha20-Poly1305 and
AES-GCM), certificate checks against the root certificates installed with
`installcerts`, redirects, the progress line, Ctrl-C and the certificate
questions at the console. Certificates go to `SYS:Prefs/Env-Archive/certs` as
on AmigaOS.

While porting I fixed some bugs in the shared code. They affect every
platform, so each one is a separate commit: certificate dates read twice,
uninitialized RSA work buffers, the P-384 reduction, the ECDSA curve chosen
from the hash instead of the key, SHA-384 and SHA-512 RSA certificate
signatures, long ASN.1 lengths, and variadic lists ended with an integer 0
instead of a null pointer.

Known limits:

- A server whose chain ends in a cross-signed copy of an installed root
  certificate, signed by a root that is no longer in the bundle, needs a
  confirmation at the console (www.google.com today).
- TLS 1.2 has no ECDHE-ECDSA cipher suites: such servers need TLS 1.3.
- The HTTP status is not checked: an error page from the server is saved as
  the file.
- x86_64: about 6 KB of memory stay allocated after each run, because the
  minimal C runtime does not free at exit.
- aarch64: the Raspberry Pi boots without a clock. Set the date first, or
  the certificates are reported as not valid today.
- aarch64: in the QEMU VM every transfer ends after about 150 seconds (slow
  USB network of the VM); on a Raspberry Pi 400 files up to 26.5 MB arrive
  complete.

Build and port notes: `AROS_PORTING.md`.

---

## 📖 Overview

`bebboget` is a small, fast HTTPS client for Amiga systems.  
It only requires `bsdsocket.library` and has **no other nonstandard dependencies**.

- Supports **SSL3.0, TLS1.0, TLS1.1, TLS1.2, TLS1.3**
- Written in C++ using a lean STL variant
- Speed‑critical functions implemented in assembly
- Based on Stefan’s Java SSL/TLS implementation (dating back to Java 1.1)

### ⚡ Performance

Tested with a 1217kB zip file on GitHub (WinUAE, original speed, no JIT):
```
| Version              | 68000 | 68020 |
|----------------------|-------|-------|
| bebboget00           | 4.8   | 28.4  |
| bebboget00 --nochpo  | 5.7   | 32.2  |
| bebboget             | —     | 49.4  |
| bebboget --nochpo    | —     | 39.8  |
```
> Note: Speed also depends on the server.

Certificates can be installed into `sys:Prefs/Env-Archive/certs`.

---

## 🛠 Programs

### `bebboget`

```text
$VER: 1.11 (26.11.2025) written by Stefan "Bebbo" Franke
USAGE: bebboget [options] <url>
Options:
-? display help
-C print outgoing headers
-D <dir> set output directory (must exist)
-H <header> add custom header
-I install all certificates
-O overwrite output file
-S print incoming headers
-T <n> timeout in seconds (default: 15)
-o <name> set output file name
-p print progress (verbosity 4 = INFO)
-q suppress progress
-v <n> set verbosity (default: 2 = ERROR)
--cipher <c> use specific cipher (default: all)
--max <n> max protocol version (default: 4)
--min <n> min protocol version (default: 3)
--nochpo disable ChaCha20‑Poly1305
--redir <n> max redirects (default: 7)
--sloppy skip signature checks
Available ciphers: TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, 
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, 
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, 
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 
	TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA, 
	TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, 
	TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_DES_CBC_SHA, TLS_RSA_WITH_RC4_128_SHA
```

---

### `installcerts`

## 📜 License

Fetch and install root certificates:

```bash
bebboget --sloppy https://curl.se/ca/cacert-2025-05-20.pem
installcerts cacert-2025-05-20.pem
```

---

### 🧪 Testing
Not extensively tested yet. Contributions welcome.

---

### GPLv3+ (General Public License, version 3 or later)

Most of the code in **bebboget** is licensed under the GNU General Public License, version 3 or later.  
This includes:

- Core HTTPS client (`bebboget`)
- Cryptographic implementations: AES, ChaCha20, DES, 3DES, RC4, GCM, MD5, Poly1305, SHA‑256, SHA‑384, SHA‑512
- Custom elliptic curve code: secp256r1, secp384r1
- All STL/ministl infrastructure and wrappers
- All javalike classes

You may redistribute and/or modify these parts under the terms of the GPLv3+.  
See <https://www.gnu.org/licenses/gpl-3.0.html> for details.

---

### Public Domain (SUPERCOP‑derived code)

Some components are derived from the SUPERCOP library (Daniel J. Bernstein, Tanja Lange, Peter Schwabe, et al.), which is released into the **public domain**.  
This includes:

- Ed25519 internal math routines
- X25519 scalar multiplication
- Supporting field arithmetic helpers

These files are explicitly marked as **Public Domain** in their headers.  
You may use, copy, modify, and distribute them without restriction.

---

### Combined Use

- The project as a whole is distributed under **GPLv3+**, but individual files marked **Public Domain** remain PD.  
- When linking or combining, the GPLv3+ terms apply to the resulting binary/library.  
- Downstream users may freely reuse the PD components in other projects without GPL obligations.

---

### ⚠️ Disclaimer of Warranty
This software is provided “AS IS”, without any warranty of any kind. The author disclaims all implied warranties, including but not limited to merchantability and fitness for a particular purpose. You assume full responsibility for using this software.

---

### 🚫 Limitation of Liability
In no event shall the author be liable for any damages suffered by you or any third party as a result of using or distributing this software. This includes, but is not limited to, lost revenue, profit, or data, or direct, indirect, special, consequential, incidental, or punitive damages, however caused and regardless of the theory of liability, even if advised of the possibility of such damages.

---

### Disclaimer

This software is provided **“AS IS”**, without warranty of any kind.  
Use at your own risk.  
See the [Disclaimer of Warranty](#⚠️-disclaimer-of-warranty) and [Limitation of Liability](#🚫-limitation-of-liability) sections for details.
