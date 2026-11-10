#!/bin/sh
# Make the Aminet and AROS Archives packages of one target.
#
#   scripts/package-aros.sh <i386|x86_64|aarch64> <build dir> <output dir> [source tag]
#
# The build dir holds bebboget and installcerts (the OUTDIR of the target's
# Makefile). The output dir gets aminet/bebboget.<target>-aros.lha with its
# .readme, arosarchives/<name>.lha with its <name>_lha.readme (the same
# archive, named as on that site) and SHA256SUMS lines. The source tag
# defaults to v<version>-aros-<target>. LHA names an LhA that can create
# archives (LHa for UNIX; lhasa only extracts).
set -eu

target=$1 bindir=$2 outdir=$3
top=$(cd "$(dirname "$0")/.." && pwd)

case $target in
i386)
	aminet=bebboget.i386-aros
	aros=bebboget.i386-aros
	tagsuffix=aros-i386-abiv0
	long='AROS i386 (the "alt-abiv0" ABI of AROS One)'
	requires="AROS One i386 (ABIv0) with a TCP/IP stack (AROSTCP)"
	other1="the AROS x86_64 build is comm/net/bebboget.x86_64-aros.lha"
	other2="the AROS aarch64 build is comm/net/bebboget.aarch64-aros.lha"
	limits=""
	;;
x86_64)
	aminet=bebboget.x86_64-aros
	aros=bebboget.x86_64-aros-v11
	tagsuffix=aros-x86_64
	long="AROS x86_64 (AROS One 64-bit, ABIv11)"
	requires="AROS One x86_64 (ABIv11) with a TCP/IP stack (AROSTCP)"
	other1="the AROS i386 build is comm/net/bebboget.i386-aros.lha"
	other2="the AROS aarch64 build is comm/net/bebboget.aarch64-aros.lha"
	limits="- x86_64: about 6 KB of memory stay allocated after each run."
	;;
aarch64)
	aminet=bebboget.aarch64-aros
	aros=bebboget.aarch64-aros
	tagsuffix=aros-aarch64
	long="AROS aarch64 (the Raspberry Pi port of AROS)"
	requires="AROS for the Raspberry Pi (aarch64) with AROSTCP"
	other1="the AROS i386 build is comm/net/bebboget.i386-aros.lha"
	other2="the AROS x86_64 build is comm/net/bebboget.x86_64-aros.lha"
	limits="- aarch64: the Raspberry Pi has no clock. Set the date first (Date), or
  the certificates are reported as not valid today.
- aarch64: the AROS system for the Raspberry Pi has no LhA. Unpack the
  archive on another computer and copy the bebboget drawer to the SD card."
	;;
*)
	echo "unknown target: $target" >&2
	exit 1
	;;
esac

for f in bebboget installcerts; do
	[ -f "$bindir/$f" ] || { echo "missing $bindir/$f" >&2; exit 1; }
done

major=$(sed -n 's/.*__VERSION_MAJOR "\([0-9]*\)".*/\1/p' "$top/include/revision.h")
minor=$(sed -n 's/.*__VERSION_MINOR "\([0-9]*\)".*/\1/p' "$top/include/revision.h")
version=$major.$minor
tag=${4:-v$version-$tagsuffix}
short="HTTPS downloader with TLS 1.3, no deps"

mkdir -p "$outdir/aminet" "$outdir/arosarchives"
outdir=$(cd "$outdir" && pwd)
am=$outdir/aminet/$aminet
ar=$outdir/arosarchives/$aros
stage=$outdir/stage-$target
rm -rf "$stage" "$am.lha" "$am.readme" "$ar.lha" "${ar}_lha.readme"
mkdir -p "$stage/bebboget"

LIMITS=$limits awk -v v="$version" -v tl="$long" -v rq="$requires" \
    -v o1="$other1" -v o2="$other2" -v tag="$tag" -v d="$(date +%d.%m.%Y)" '
	/^@ARCH_LIMITS@$/ { if (ENVIRON["LIMITS"] != "") print ENVIRON["LIMITS"]; next }
	{
		gsub(/@VERSION@/, v); gsub(/@TARGET_LONG@/, tl); gsub(/@REQUIRES@/, rq)
		gsub(/@OTHER1@/, o1); gsub(/@OTHER2@/, o2)
		gsub(/@SOURCE_TAG@/, tag); gsub(/@DATE@/, d)
		print
	}' "$top/packaging/aros/bebboget.readme.in" > "$stage/body"

# Aminet: Architecture i386-aros on every AROS target (the only AROS value,
# as for BebboSSH); the uploader address is a real one, Aminet hides it.
{
	printf 'Short:        %s\n' "$short"
	printf 'Author:       Stefan Franke (bebboget), Michele Dipace (AROS port)\n'
	printf 'Uploader:     michele.dipace@kaffeine.net (Michele Dipace)\n'
	printf 'Type:         comm/net\n'
	printf 'Version:      %s\n' "$version"
	printf 'Requires:     %s\n' "$requires"
	printf 'Architecture: i386-aros\n\n'
	cat "$stage/body"
} > "$am.readme"

# AROS Archives: its own header up to hend:, then the same body. license
# takes only the site's values (GPL).
{
	printf 'name: bebboget\n'
	printf 'description: %s\n' "$short"
	printf 'version: %s\n' "$version"
	printf 'author: Stefan Franke, Michele Dipace\n'
	printf 'submitter: Michele Dipace\n'
	printf 'email: michele.dipace@kaffeine.net\n'
	printf 'url: https://github.com/kaffeine1/bebboget-aros\n'
	printf 'donateurl: https://ko-fi.com/kaffeine1\n'
	printf 'category: network/misc\n'
	printf 'requirements: %s\n' "$requires"
	printf 'license: GPL\n'
	printf 'distribute: yes\n'
	printf 'hend:\n'
	cat "$stage/body"
} > "${ar}_lha.readme"

# Aminet rules: Short up to 40 characters, lines up to 78 columns, ASCII and
# LF only, file names up to 30 characters.
fail=0
[ ${#short} -le 40 ] || { echo "Short longer than 40" >&2; fail=1; }
for f in "$am.readme" "${ar}_lha.readme"; do
	if LC_ALL=C grep -q "$(printf '[\r\200-\377]')" "$f"; then
		echo "$f: CR or non-ASCII byte" >&2; fail=1
	fi
done
awk 'length > 78 { print FILENAME ": line " NR " has " length " columns"; bad = 1 }
	END { exit bad }' "$am.readme" >&2 || fail=1
for f in "$aminet.lha" "$aminet.readme"; do
	[ ${#f} -le 30 ] || { echo "$f: name longer than 30" >&2; fail=1; }
done
[ $fail -eq 0 ] || exit 1

cp "$bindir/bebboget" "$bindir/installcerts" "$stage/bebboget/"
chmod 755 "$stage/bebboget/bebboget" "$stage/bebboget/installcerts"
cp "$am.readme" "$stage/bebboget/bebboget.readme"
cp "$top/COPYING" "$top/LICENSE" "$stage/bebboget/"

(cd "$stage" && COPYFILE_DISABLE=1 "${LHA:-lha}" aq --ignore-mac-files "$am.lha" bebboget)
cp "$am.lha" "$ar.lha"
rm -rf "$stage"
(cd "$outdir" && shasum -a 256 "aminet/$aminet.lha" "aminet/$aminet.readme" \
	"arosarchives/$aros.lha" "arosarchives/${aros}_lha.readme") >> "$outdir/SHA256SUMS"
echo "$am.lha"
echo "$ar.lha"
