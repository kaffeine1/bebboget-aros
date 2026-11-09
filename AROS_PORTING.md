# bebboget AROS Porting Notes

One source tree builds three AROS targets. The m68k assembly is not used: the
AROS builds take the C code paths of the Linux build.

| Target | Build entry point | Toolchain |
| --- | --- | --- |
| i386 `alt-abiv0` (AROS One 32-bit) | `Makefile.aros` | `i386-aros` GCC 6.5 with the AROS One i386 SDK |
| x86_64 `mincrt` (AROS One 64-bit) | `Makefile.aros-x86_64` | `x86_64-aros` crosstools GCC 10.5 |
| aarch64 (`raspi-aarch64`) | `Makefile.aros-aarch64` | `aarch64-aros` GCC 6.5 with a raspi-aarch64 sysroot |

Each build makes `bebboget`, `installcerts` and the self-tests (`test*`).

## Upstream and license

The port is a derivative of Stefan "Bebbo" Franke's bebboget
(https://franke.ms/git/bebbo/bebboget), based on upstream 1.11, commit
`9b223f1`. The upstream server only serves its last nine commits, so this
repository starts from them with rewritten hashes; later upstream changes are
applied as patches.

The AROS changes are by Michele Dipace <michele.dipace@kaffeine.net>, GNU GPL
v3 or later like the upstream code. `src/aros_mincrt.c`,
`include/aros_mincrt_wrappers.h`, `src/aros_startup_flags.c`,
`src/aros_randpool.cpp` and `include/compat_endian.h` come from my BebboSSH
AROS port (https://github.com/kaffeine1/bebbossh-aros).

## Build

i386, with the AROS One i386 SDK:

    make -f Makefile.aros all CC=i386-aros-gcc CXX=i386-aros-g++ \
      AR=i386-aros-ar STRIP=i386-aros-strip \
      AROS_SDK_ROOT=<AROS One i386 SDK>/Development

x86_64, with `x86_64-aros-gcc` in `PATH` and the AROS One x86_64 SDK in
`~/amiga-dev/sdks/aros-one-x86_64` (for `startup.o`, see
`AROS_X86_64_RUNTIME_SDK`):

    CC=x86_64-aros-gcc CXX=x86_64-aros-g++ AR=x86_64-aros-ar \
    STRIP=x86_64-aros-strip OBJCOPY=x86_64-aros-objcopy \
      make -f Makefile.aros-x86_64 all

aarch64:

    make -f Makefile.aros-aarch64 all AROS_TOOLCHAIN=<toolchain dir> \
      SYSROOT=<AROS raspi-aarch64 build>/bin/raspi-aarch64/AROS/Developer

Release archives, one per target, with an LhA that can create archives (LHa
for UNIX; lhasa only extracts):

    LHA=<lha> scripts/package-aros.sh <i386|x86_64|aarch64> <build dir> <output dir>

Each gives `aminet/bebboget.<target>-aros.lha` with its `.readme` and the
same archive for The AROS Archives in `arosarchives/` (`bebboget.i386-aros`,
`bebboget.x86_64-aros-v11`, `bebboget.aarch64-aros`, with a `_lha.readme`).
Both readmes share the body in `packaging/aros/bebboget.readme.in`; its
source link points to the tag `v<version>-aros-<target>` (`i386-abiv0` for
i386).

## What the port changes

- `src/socket_glue_aros.c`: on AROS the socket calls exist only as macros of
  `proto/bsdsocket.h`, which cannot be used as `::connect()` and so on in C++.
  The glue turns them into functions; `src/socket.cpp` sees only the
  prototypes. bsdsocket.library is opened by the startup code (`ADD2LIBS`), on
  x86_64 at the first socket call.
- `src/bebboget.cpp` and `src/certstuff.cpp` use the AmigaDOS calls of the
  Amiga build (console size, Ctrl-C, files, certificate directory) on AROS too.
- `randfill()` is the SHA-512 entropy pool of BebboSSH AROS
  (`src/aros_randpool.cpp`), with the seed file `ENVARC:bebboget/random_seed`.
  The Amiga code read the custom chips, which do not exist on AROS.
- x86_64: the AROS One libraries expect their base in `r12`, while the
  crosstools headers pass it as a C argument. The build uses the minimal C
  runtime of BebboSSH AROS, where every library call goes through a wrapper
  that loads `r12`. `src/aros_mincrt_stdio.c` adds what bebboget needs: the
  C++ static constructors, the posixc stdio entry points the headers map
  stdio to (`%ld` read as 32 bit), `gmtime()`, `ctime()`, `mktime()` and
  `sscanf()`. `fflush(stdin)` drops the argument line that `RunCommand()`
  puts into the `Input()` buffer, so the certificate question waits for an
  answer.
- aarch64: `-ffixed-x18`, `-fno-common` and `-fsigned-char`, as in BebboSSH
  AROS.

## Checks on x86_64

After a build, every binary has byte 8 of the ELF header set to `0x0B` and
no `.got` section (`POST_LINK`), and every library vector call in the objects
must be preceded by a load of `r12`. With
`x86_64-aros-objdump -d <object>` the only vector calls are the wrappers in
`aros_mincrt.o` and the two `dos.library` calls of `startup.o`.

## Tests

On AROS One i386 and x86_64 under QEMU: the self-tests, `installcerts` with
the curl CA bundle, certificate checks for curl.se, aminet.net, github.com,
www.wikipedia.org, letsencrypt.org and cdn.kernel.org, and downloads compared
with published SHA-256 sums over TLS 1.3 (ChaCha20-Poly1305, AES-128-GCM,
AES-256-GCM) and TLS 1.2 (ECDHE-RSA-AES128-GCM), with redirects and files up
to 18.7 MB.

On the aarch64 `raspi3b` VM: the self-tests and the same certificate checks.
Its USB network ends every transfer after about 150 seconds, so files over
about 130 KB do not complete there; the bytes that arrive match the
reference files. The known limits are listed in `README.md`.
