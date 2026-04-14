#!/bin/bash
# Build script for SecureWrapper
# Cross-compiles for Linux, macOS, and Windows (amd64 + arm64)
# Auto-increments build number on each build

set -euo pipefail

export PATH=~/go-sdk/go/bin:$PATH
export GOPATH=~/go

# Version management
VERSION_FILE=".version"
MAJOR=0
MINOR=1

# Read or initialize build number
if [ -f "$VERSION_FILE" ]; then
    BUILD=$(cat "$VERSION_FILE")
else
    BUILD=0
fi

BUILD=$((BUILD + 1))
echo "$BUILD" > "$VERSION_FILE"

FULL_VERSION="${MAJOR}.${MINOR}.${BUILD}"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

TARGETS=(
    "linux:amd64"
    "linux:arm64"
    "darwin:amd64"
    "darwin:arm64"
    "windows:amd64"
)

OUTDIR="dist"
mkdir -p "$OUTDIR"

echo "Building SecureWrapper v${FULL_VERSION}..."
echo ""

LDFLAGS="-s -w -X 'main.version=${FULL_VERSION}' -X 'main.buildDate=${BUILD_DATE}'"

for target in "${TARGETS[@]}"; do
    IFS=":" read -r os arch <<< "$target"

    ext=""
    if [ "$os" = "windows" ]; then
        ext=".exe"
    fi

    outfile="$OUTDIR/wrapper-${os}-${arch}${ext}"

    printf "  %-25s" "${os}/${arch}"

    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
        -ldflags="$LDFLAGS" \
        -o "$outfile" \
        . 2>&1

    chmod +x "$outfile"
    size=$(ls -lh "$outfile" | awk '{print $5}')
    echo "OK  ($size)"
done

# Generate SHA256SUMS for release verification
cd "$OUTDIR"
sha256sum wrapper-* > SHA256SUMS
cd ..

# Copy the native binary to ./wrapper for local use
cp "$OUTDIR/wrapper-linux-amd64" ./wrapper
chmod +x ./wrapper

echo ""
echo "SecureWrapper v${FULL_VERSION} (built ${BUILD_DATE})"
echo "Built $(ls -1 $OUTDIR/ | wc -l) binaries in $OUTDIR/"
echo "Local binary: ./wrapper (linux-amd64)"
echo ""
echo "NOTE: Each binary has a unique hash. Vaults are bound to the specific binary."
