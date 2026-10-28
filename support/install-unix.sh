#!/bin/sh
set -eu

VERSION="0.1.0-testnet.10"
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64|aarch64) TARGET="macos-aarch64" ;;
      x86_64|amd64) TARGET="macos-x86_64" ;;
      *) printf '%s\n' 'Unsupported macOS architecture' >&2; exit 1 ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      aarch64|arm64) TARGET="linux-aarch64" ;;
      x86_64|amd64) TARGET="linux-x86_64" ;;
      *) printf '%s\n' 'Unsupported Linux architecture' >&2; exit 1 ;;
    esac
    ;;
  *) printf '%s\n' 'This installer supports macOS and Linux' >&2; exit 1 ;;
esac

BASE="https://github.com/emyrinj/astatine-miner/releases/download/v${VERSION}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
MANIFEST="$TEMP_DIR/update-manifest.txt"
SIGNATURE="$TEMP_DIR/update-manifest.sig"
PUBLIC_KEY="$TEMP_DIR/release-signing-public.pem"
ASSET_LINE="$TEMP_DIR/asset-line"

curl --fail --show-error --location --connect-timeout 10 --max-time 60 --max-filesize 2097152 "$BASE/update-manifest.txt" -o "$MANIFEST"
curl --fail --show-error --location --connect-timeout 10 --max-time 60 --max-filesize 4096 "$BASE/update-manifest.sig" -o "$SIGNATURE"
cat > "$PUBLIC_KEY" <<'PUBLIC_KEY_EOF'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvFRqlV94vTfLogc01RAk
RPzmEYGO62akKkOLpBtaBqemy4gjOpDZAjSWn2wsPilPAvGQT2UWvck56GlUbv7v
Rzz17AvPf7cwKv+hYGCQA/5WEmhxhgLUSei44ihW5AAFC068U8iD37CwMEPDy23u
4jl35HKwvEd5xasdaz8db8cX/9pquUdOL3mGnPpTXkzZqQHnkEEA42jKo8jKpl0I
DTlVoKZ8Kdw6BBnzGLhizJtZGiDj5J3hH5YHrT5weh8RBDnqKSj8xNiGhgsDh5xV
TUsttFfjlOFHrCHrkED3+UG01xJ5PYFyos4QSO7feLkbjlpOfh1x8pMlQ96YXIZ3
mxNDltLgXqJ98/IzVvp/ewLmIkGY6pW5Exlvdbz6nfgtcbaiXCi9MwbevAojzLJ1
V/wps7F/hyuv9dKSRIoaRIHkgSnA6YP8epTnJn+swL9LHdZjayS1vkXf8s46IAaL
yh8ts3pJY8Tb5gAIzJ6OvDxijD1AnnhrMEew9lcVVW6HAgMBAAE=
-----END PUBLIC KEY-----
PUBLIC_KEY_EOF

openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE" "$MANIFEST" >/dev/null
manifest_repository="$(awk -F= '$1 == "repository" { print $2 }' "$MANIFEST")"
manifest_channel="$(awk -F= '$1 == "channel" { print $2 }' "$MANIFEST")"
manifest_version="$(awk -F= '$1 == "version" { print $2 }' "$MANIFEST")"
test "$manifest_repository" = "emyrinj/astatine-miner"
test "$manifest_channel" = "testnet"
test "$manifest_version" = "$VERSION"
asset_key="asset.package.${TARGET}="
awk -F= -v key="$asset_key" '$1 == substr(key, 1, length(key) - 1) { print $2 }' "$MANIFEST" > "$ASSET_LINE"
IFS='|' read -r ASSET EXPECTED_SHA256 EXPECTED_SIZE < "$ASSET_LINE"
if [ -z "${ASSET:-}" ] || [ -z "${EXPECTED_SHA256:-}" ] || [ -z "${EXPECTED_SIZE:-}" ]; then
  printf '%s\n' 'Signed manifest has no package for this platform' >&2
  exit 1
fi
test "$ASSET" = "astatine-${TARGET}.tar.gz"

ARCHIVE="$TEMP_DIR/$ASSET"
curl --fail --show-error --location --connect-timeout 10 --max-time 180 --max-filesize "$EXPECTED_SIZE" --retry 2 --retry-max-time 240 --progress-bar "$BASE/$ASSET" -o "$ARCHIVE"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | awk '{ print $1 }')"
else
  ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE" | awk '{ print $1 }')"
fi
ACTUAL_SIZE="$(wc -c < "$ARCHIVE" | tr -d '[:space:]')"
test "$ACTUAL_SHA256" = "$EXPECTED_SHA256"
test "$ACTUAL_SIZE" = "$EXPECTED_SIZE"

tar_entries="$(tar -tzf "$ARCHIVE")"
expected_entries="$(printf '%s\n' astatine LICENSE-MIT THIRD_PARTY_LICENSES.md)"
test "$tar_entries" = "$expected_entries"
tar -xzf "$ARCHIVE" -C "$TEMP_DIR"
"$TEMP_DIR/astatine" --version | awk -v version="$VERSION" 'index($0, version) { found = 1 } END { exit !found }'

INSTALL_DIR="${HOME:?HOME is required}/.local/bin"
LICENSE_DIR="$INSTALL_DIR/licenses"
if [ -x "$INSTALL_DIR/astatine" ]; then
  installed_version="$("$INSTALL_DIR/astatine" --version 2>/dev/null | awk 'NR == 1 { print $2 }' || true)"
  case "$installed_version" in
    0.1.0-testnet.*)
      installed_sequence="${installed_version##*.}"
      candidate_sequence="${VERSION##*.}"
      case "$installed_sequence" in
        ''|*[!0-9]*) ;;
        *)
          if [ "$installed_sequence" -gt "$candidate_sequence" ]; then
            printf '%s\n' "Refusing to replace newer Astatine $installed_version with $VERSION" >&2
            exit 1
          fi
          ;;
      esac
      ;;
  esac
fi
mkdir -p "$LICENSE_DIR"
install -m 0755 "$TEMP_DIR/astatine" "$INSTALL_DIR/.astatine.update"
install -m 0644 "$TEMP_DIR/LICENSE-MIT" "$LICENSE_DIR/.LICENSE-MIT.update"
install -m 0644 "$TEMP_DIR/THIRD_PARTY_LICENSES.md" "$LICENSE_DIR/.THIRD_PARTY_LICENSES.md.update"
mv -f "$INSTALL_DIR/.astatine.update" "$INSTALL_DIR/astatine"
mv -f "$LICENSE_DIR/.LICENSE-MIT.update" "$LICENSE_DIR/LICENSE-MIT"
mv -f "$LICENSE_DIR/.THIRD_PARTY_LICENSES.md.update" "$LICENSE_DIR/THIRD_PARTY_LICENSES.md"
"$INSTALL_DIR/astatine" --version
printf '%s\n' "Installed authenticated Astatine $VERSION in $INSTALL_DIR"
