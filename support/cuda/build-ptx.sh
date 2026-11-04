#!/bin/sh
set -eu

IMAGE='nvidia/cuda@sha256:0cca95cbbdbdc5011919e5182891bc944a159b9c529999c1e434b6406fa90f53'
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
SOURCE="$ROOT/src/gpu/cuda"

if [ "$#" -ne 1 ]; then
  printf '%s\n' 'Usage: support/cuda/build-ptx.sh OUTPUT_PTX_PATH' >&2
  exit 2
fi

OUTPUT=$1
if [ -e "$OUTPUT" ]; then
  printf '%s\n' "Refusing to overwrite existing CUDA PTX output: $OUTPUT" >&2
  exit 1
fi
mkdir -p "$(dirname -- "$OUTPUT")"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/astatine-cuda-ptx.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

docker run --rm --platform linux/amd64 \
  --mount "type=bind,src=$SOURCE,dst=/source,readonly" \
  --mount "type=bind,src=$WORK,dst=/output" \
  --entrypoint /bin/bash \
  "$IMAGE" \
  -euo pipefail -c '
    nvcc --version
    nvcc --std=c++14 --gpu-architecture=compute_52 --ptx --optimize=3 \
      --output-file=/output/sha256d.ptx /source/sha256d.cu
    ptxas -v --gpu-name sm_86 /output/sha256d.ptx -o /output/sha256d-sm86.cubin
    sed -i "\$ { /^\$/d; }" /output/sha256d.ptx
  '

test -s "$WORK/sha256d.ptx"
install -m 0644 "$WORK/sha256d.ptx" "$OUTPUT"
printf 'Generated CUDA PTX with pinned image %s\n' "$IMAGE"
