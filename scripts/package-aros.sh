#!/bin/sh
# Make the AROS release archive of one target.
#
#   scripts/package-aros.sh <i386|x86_64|aarch64> <build dir> <output dir> [source ref]
#
# The build dir holds bebboget and installcerts (the OUTDIR of the target's
# Makefile). The output dir gets bebboget-aros-<target>.lha, the matching
# .readme for Aminet and SHA256SUMS lines. The source ref defaults to the
# current commit. LHA names an LhA that can create archives (LHa for UNIX;
# lhasa only extracts).
set -eu

target=$1 bindir=$2 outdir=$3
top=$(cd "$(dirname "$0")/.." && pwd)
ref=${4:-commit $(git -C "$top" rev-parse --short HEAD)}

case $target in
i386)
	token=i386-aros
	long="AROS One i386 (32 bit, ABI v0)"
	limits=""
	;;
x86_64)
	token=x86_64-aros
	long="AROS One x86_64 (64 bit)"
	limits="- x86_64: about 6 KB of memory stay allocated after each run."
	;;
aarch64)
	token=aarch64-aros
	long="AROS on the Raspberry Pi (aarch64)"
	limits="- aarch64: tested in QEMU (raspi3b) only, not yet on a real Raspberry Pi.
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
name=bebboget-aros-$target

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
stage=$outdir/stage-$target
rm -rf "$stage" "$outdir/$name.lha" "$outdir/$name.readme"
mkdir -p "$stage/bebboget"

# Aminet: 78 columns, LF, the readme next to the archive and inside it.
LIMITS=$limits awk -v v="$version" -v tok="$token" -v ts="$target" -v tl="$long" \
    -v ref="$ref" -v d="$(date +%d.%m.%Y)" '
	/^@ARCH_LIMITS@$/ { if (ENVIRON["LIMITS"] != "") print ENVIRON["LIMITS"]; next }
	{
		gsub(/@VERSION@/, v); gsub(/@ARCH_TOKEN@/, tok)
		gsub(/@TARGET_SHORT@/, ts); gsub(/@TARGET_LONG@/, tl)
		gsub(/@SOURCE_REF@/, ref); gsub(/@DATE@/, d)
		print
	}' "$top/packaging/aros/bebboget.readme.in" > "$outdir/$name.readme"
if awk 'length > 78 { exit 1 }' "$outdir/$name.readme"; then :; else
	echo "a line of $name.readme is longer than 78 columns" >&2
	exit 1
fi

cp "$bindir/bebboget" "$bindir/installcerts" "$stage/bebboget/"
chmod 755 "$stage/bebboget/bebboget" "$stage/bebboget/installcerts"
cp "$outdir/$name.readme" "$stage/bebboget/bebboget.readme"
cp "$top/COPYING" "$top/LICENSE" "$stage/bebboget/"

(cd "$stage" && COPYFILE_DISABLE=1 "${LHA:-lha}" aq --ignore-mac-files "$outdir/$name.lha" bebboget)
rm -rf "$stage"
(cd "$outdir" && shasum -a 256 "$name.lha" "$name.readme") >> "$outdir/SHA256SUMS"
echo "$outdir/$name.lha"
