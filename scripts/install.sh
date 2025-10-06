#!/usr/bin/env bash
# installs the latest (or requested) zblock release for the current platform
set -euo pipefail

REPO="lorenries/zblock"
PROGRAM="zblock"

log() {
  printf '%s\n' "$*"
}

error() {
  printf 'zblock-install: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  -v, --version <tag>     Install a specific release tag (default: latest)
      --install-dir <dir> Root directory for installation (default: $HOME/.zblock)
      --bin-dir <dir>     Directory to place executables (default: <install-dir>/bin)
  -h, --help              Show this help message

Environment overrides:
  ZBLOCK_VERSION, ZBLOCK_INSTALL_DIR, ZBLOCK_BIN_DIR
EOF
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    error "required tool '$1' not found in PATH"
  fi
}

resolve_latest_tag() {
  local latest_url
  latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") || \
    error "unable to resolve latest release tag"
  printf '%s' "${latest_url##*/}"
}

to_posix_path() {
  # best-effort conversion; useful for path hints
  printf '%s' "${1/#$HOME/~}"
}

# Defaults (capture env overrides later)
version=${ZBLOCK_VERSION:-latest}
install_dir_override=${ZBLOCK_INSTALL_DIR:-}
bin_dir_override=${ZBLOCK_BIN_DIR:-}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)
      [[ $# -lt 2 ]] && error "missing value for $1"
      version="$2"
      shift 2
      ;;
    --install-dir)
      [[ $# -lt 2 ]] && error "missing value for --install-dir"
      install_dir_override="$2"
      shift 2
      ;;
    --bin-dir)
      [[ $# -lt 2 ]] && error "missing value for --bin-dir"
      bin_dir_override="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      error "unknown option '$1'"
      ;;
  esac
done

require_tool curl
require_tool unzip
require_tool mktemp
require_tool install

uname_s=$(uname -s)
uname_m=$(uname -m)

case "$uname_s" in
  Darwin)
    os_label="macOS"
    ;;
  Linux)
    os_label="Linux"
    ;;
  *)
    error "unsupported operating system '$uname_s'"
    ;;
esac

case "$uname_m" in
  x86_64|amd64)
    arch_label="x86_64"
    ;;
  arm64|aarch64)
    arch_label="arm64"
    ;;
  *)
    error "unsupported architecture '$uname_m'"
    ;;
esac

if [[ "$version" == "latest" ]]; then
  version=$(resolve_latest_tag)
fi

artifact="${PROGRAM}-${version}-${os_label}-${arch_label}.zip"
download_url="https://github.com/${REPO}/releases/download/${version}/${artifact}"

install_root=${install_dir_override:-$HOME/.zblock}
bin_dir=${bin_dir_override:-$install_root/bin}

tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t zblock)
trap 'rm -rf "$tmp_dir"' EXIT

archive_path="$tmp_dir/$artifact"
log "Downloading ${artifact} (${version}) for ${os_label}/${arch_label}..."
curl --fail --location --progress-bar "$download_url" --output "$archive_path" || \
  error "failed to download archive from $download_url"

extract_dir="$tmp_dir/extracted"
mkdir -p "$extract_dir"
unzip -q "$archive_path" -d "$extract_dir" || error "failed to extract archive"

payload_dir="$extract_dir/zblock"
if [[ ! -d "$payload_dir" ]]; then
  error "unexpected archive layout: missing 'zblock' directory"
fi

mkdir -p "$bin_dir"
install -m 0755 "$payload_dir/zblock" "$bin_dir/zblock"
install -m 0755 "$payload_dir/zblockd" "$bin_dir/zblockd"

log "Installed zblock binaries to $(to_posix_path "$bin_dir")"

if ! command -v zblock >/dev/null 2>&1; then
  if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
    log "Add the following to your shell profile to use zblock:"
    log "  export PATH=\"$bin_dir:\$PATH\""
  fi
fi

log "Next steps:"
log "  1. Ensure '$bin_dir' is on your PATH (open a new shell after updating)"
log "  2. Run 'sudo $(to_posix_path "$bin_dir/zblock") init' to set up system components"
log "  3. Use 'zblock start --for <minutes>' to begin a blocking session"

if command -v zblock >/dev/null 2>&1; then
  log "Run 'zblock --help' to explore available commands."
else
  log "After updating your PATH, open a new shell and run 'zblock --help'."
fi

log "Done. Installed version: ${version}."
