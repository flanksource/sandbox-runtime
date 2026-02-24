#!/usr/bin/env bash
set -euo pipefail

# Build static seccomp binaries for Linux using Docker
# Output: third_party/seccomp/{x64,arm64}/unix-block.bpf and apply-seccomp

echo "Building static seccomp binaries using Docker..."

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is required but not installed"
  exit 1
fi

SOURCE_DIR="$ROOT_DIR/third_party/seccomp-src"
if [ ! -d "$SOURCE_DIR" ]; then
  echo "Error: Source directory not found: $SOURCE_DIR"
  exit 1
fi

PLATFORMS=(
  "linux/amd64:x64:ubuntu:22.04"
  "linux/arm64:arm64:ubuntu:22.04"
)

build_platform() {
  local docker_platform="$1"
  local vendor_dir="$2"
  local base_image="$3"
  local image_version="$4"

  local output_dir="$ROOT_DIR/third_party/seccomp/$vendor_dir"
  local bpf_file="$output_dir/unix-block.bpf"
  local apply_seccomp_bin="$output_dir/apply-seccomp"

  echo ""
  echo "=========================================="
  echo "Building for: $vendor_dir ($docker_platform)"
  echo "=========================================="

  if [ -f "$bpf_file" ] && [ -f "$apply_seccomp_bin" ]; then
    echo "⊙ Files already exist, skipping build"
    return 0
  fi

  mkdir -p "$output_dir"

  docker run --rm --platform "$docker_platform" \
    -v "$SOURCE_DIR:/src:ro" \
    -v "$output_dir:/output" \
    "$base_image:$image_version" sh -c "
      set -e
      apt-get update -qq
      apt-get install -y -qq gcc libseccomp-dev file > /dev/null

      gcc -o /output/seccomp-unix-block /src/seccomp-unix-block.c \
          -static -lseccomp \
          -O2 -Wall -Wextra

      strip /output/seccomp-unix-block
      chmod +x /output/seccomp-unix-block

      gcc -o /output/apply-seccomp /src/apply-seccomp.c \
          -static \
          -O2 -Wall -Wextra

      strip /output/apply-seccomp
      chmod +x /output/apply-seccomp
    "

  "$output_dir/seccomp-unix-block" "$bpf_file"

  if [ ! -f "$bpf_file" ] || [ ! -f "$apply_seccomp_bin" ]; then
    echo "✗ Error: failed generating seccomp artifacts for $vendor_dir"
    exit 1
  fi

  rm -f "$output_dir/seccomp-unix-block"

  echo "✓ Built seccomp artifacts for $vendor_dir"
}

FAILED=()
for platform_spec in "${PLATFORMS[@]}"; do
  IFS=':' read -r docker_platform vendor_dir base_image image_version <<< "$platform_spec"
  if ! build_platform "$docker_platform" "$vendor_dir" "$base_image" "$image_version"; then
    FAILED+=("$vendor_dir")
  fi
done

echo ""
echo "=========================================="
echo "Build Summary"
echo "=========================================="

if [ ${#FAILED[@]} -eq 0 ]; then
  echo "✓ All platforms built successfully"
  find "$ROOT_DIR/third_party/seccomp" \( -name "*.bpf" -o -name "apply-seccomp" \) -type f | sort
  exit 0
fi

echo "✗ Failed for: ${FAILED[*]}"
exit 1
