#!/usr/bin/env bash
# Install the pinned, test-only Anvil binary on Linux x86_64.
#
# The release inventory is support/linux/anvil-release.json. The archive is
# downloaded over HTTPS, its pinned SHA-256 is verified before extraction, and
# the extracted executable is smoke-checked. No shell installer or unpinned
# "latest" channel is used. This binary is test infrastructure only.
set -euo pipefail

usage() {
    printf 'usage: %s INSTALL_DIR\n' "$0" >&2
    exit 2
}

if [[ $# -ne 1 ]]; then
    usage
fi

install_dir="$1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
manifest="$script_dir/anvil-release.json"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'install-anvil: Linux is required for the pinned distribution asset\n' >&2
    exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
    printf 'install-anvil: x86_64 is required for the pinned distribution asset\n' >&2
    exit 1
fi
for tool in curl python3 sha256sum tar install file; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'install-anvil: required tool is missing: %s\n' "$tool" >&2
        exit 1
    fi
done
if [[ ! -f "$manifest" ]]; then
    printf 'install-anvil: release inventory is missing: %s\n' "$manifest" >&2
    exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/astatine-anvil.XXXXXX")"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT
release_file="$work/release-fields"
if ! python3 - "$manifest" >"$release_file" <<'PY'
import json
import pathlib
import re
import sys

manifest = pathlib.Path(sys.argv[1])
data = json.loads(manifest.read_text(encoding="utf-8"))
if data.get("schema") != "astatine-external-binary-release/v1":
    raise SystemExit("unsupported release inventory schema")
if data.get("tool") != "anvil" or data.get("platform") != "linux-amd64":
    raise SystemExit("release inventory does not describe Linux amd64 Anvil")
for key in ("release_tag", "source_commit", "asset", "asset_url", "sha256", "sha256_url"):
    if not isinstance(data.get(key), str) or not data[key]:
        raise SystemExit(f"release inventory field is missing: {key}")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", data["release_tag"]):
    raise SystemExit("release inventory tag is not a pinned semantic version")
if not re.fullmatch(r"foundry_v[0-9]+\.[0-9]+\.[0-9]+_linux_amd64\.tar\.gz", data["asset"]):
    raise SystemExit("release inventory asset name is not the pinned Linux amd64 archive")
expected_base = (
    "https://github.com/foundry-rs/foundry/releases/download/"
    f"{data['release_tag']}/{data['asset']}"
)
if data["asset_url"] != expected_base:
    raise SystemExit("release inventory asset URL is not the pinned upstream HTTPS URL")
expected_checksum_url = expected_base.removesuffix(".tar.gz") + ".sha256"
if data["sha256_url"] != expected_checksum_url:
    raise SystemExit("release inventory checksum URL is not the pinned upstream HTTPS URL")
digest = data["sha256"]
if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
    raise SystemExit("release inventory SHA-256 is malformed")
commit = data["source_commit"]
if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
    raise SystemExit("release inventory source commit is malformed")
asset_bytes = data.get("asset_bytes")
if not isinstance(asset_bytes, int) or isinstance(asset_bytes, bool) or not 50_000_000 <= asset_bytes <= 300_000_000:
    raise SystemExit("release inventory archive size is missing or outside the supported bound")
for key in ("release_tag", "source_commit", "asset", "asset_url", "sha256", "sha256_url", "asset_bytes"):
    print(data[key])
PY
then
    printf 'install-anvil: release inventory validation failed\n' >&2
    exit 1
fi
mapfile -t release < "$release_file"
tag="${release[0]}"
source_commit="${release[1]}"
asset="${release[2]}"
asset_url="${release[3]}"
expected_sha256="${release[4]}"
sha256_url="${release[5]}"
expected_bytes="${release[6]}"

archive="$work/foundry.tar.gz"
curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
    --max-filesize "$expected_bytes" --output "$archive" "$asset_url"

actual_bytes="$(wc -c < "$archive" | tr -d ' ')"
if [[ "$actual_bytes" != "$expected_bytes" ]]; then
    printf 'install-anvil: size mismatch for %s: expected %s bytes, got %s bytes\n' \
        "$asset" "$expected_bytes" "$actual_bytes" >&2
    exit 1
fi
actual_sha256="$(sha256sum "$archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    printf 'install-anvil: SHA-256 mismatch for %s: expected %s, got %s\n' \
        "$tag" "$expected_sha256" "$actual_sha256" >&2
    exit 1
fi

mkdir -p "$work/extracted"
tar --no-same-owner -xzf "$archive" -C "$work/extracted" anvil
if [[ ! -f "$work/extracted/anvil" ]]; then
    printf 'install-anvil: pinned archive did not contain anvil\n' >&2
    exit 1
fi
if ! file "$work/extracted/anvil" | grep -q 'ELF 64-bit.*x86-64'; then
    printf 'install-anvil: extracted anvil is not an x86-64 ELF executable\n' >&2
    exit 1
fi

install -d -m 0755 "$install_dir/bin"
install -m 0755 "$work/extracted/anvil" "$install_dir/bin/anvil"
version_output="$("$install_dir/bin/anvil" --version 2>&1 | sed -n '1p')"
case "$version_output" in
    "anvil Version: ${tag#v}"|"anvil Version: ${tag#v}-"*|"anvil Version: ${tag#v}+"*) ;;
    *)
        printf 'install-anvil: unexpected Anvil version output: %s\n' "$version_output" >&2
        exit 1
        ;;
esac
reported_commit="$("$install_dir/bin/anvil" --version 2>&1 | awk '$1 == "Commit" && $2 == "SHA:" { print $3; exit }')"
if [[ "$reported_commit" != "$source_commit" ]]; then
    printf 'install-anvil: Anvil commit mismatch: expected %s, got %s\n' \
        "$source_commit" "${reported_commit:-<missing>}" >&2
    exit 1
fi

printf 'install-anvil: installed pinned %s from %s\n' "$tag" "$asset_url"
printf 'install-anvil: sha256 %s (enforced)\n' "$expected_sha256"
printf 'install-anvil: source commit %s (enforced in version banner)\n' "$source_commit"
printf 'install-anvil: recorded checksum source (pinned digest enforced) %s\n' "$sha256_url"
printf 'install-anvil: %s\n' "$version_output"
