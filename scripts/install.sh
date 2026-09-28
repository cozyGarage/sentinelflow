#!/usr/bin/env bash
# Install SentinelFlow from GitHub Releases into ./bin (or INSTALL_DIR).
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/cozyGarage/sentielflow/main/scripts/install.sh | bash
#   VERSION=1.0.0 ./scripts/install.sh
# Verifies the downloaded archive against checksums.txt from the same release.
set -euo pipefail

REPO="${REPO:-cozyGarage/sentielflow}"
INSTALL_DIR="${INSTALL_DIR:-${PWD}/bin}"
VERSION="${VERSION:-}"
SKIP_CHECKSUM="${SKIP_CHECKSUM:-0}"

detect_os() {
  case "$(uname -s)" in
    Linux*) echo linux ;;
    Darwin*) echo darwin ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
}

github_curl() {
  local url="$1"
  local dest="$2"
  local args=(-fsSL)
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json")
  fi
  curl "${args[@]}" "${url}" -o "${dest}"
}

verify_cosign() {
  local checksums="$1"
  local sig="${checksums}.sig"
  local cert="${checksums}.pem"
  if [[ "${VERIFY_SIGNATURE:-0}" != "1" ]]; then
    return 0
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    echo "VERIFY_SIGNATURE=1 but cosign is not installed" >&2
    exit 1
  fi
  if [[ ! -f "${sig}" || ! -f "${cert}" ]]; then
    echo "missing ${sig} or ${cert} for keyless verification" >&2
    exit 1
  fi
  local identity="${COSIGN_IDENTITY_REGEXP:-https://github.com/${REPO}/.*}"
  local issuer="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
  cosign verify-blob \
    --certificate "${cert}" \
    --signature "${sig}" \
    --certificate-identity-regexp "${identity}" \
    --certificate-oidc-issuer "${issuer}" \
    "${checksums}"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    echo "need sha256sum or shasum to verify checksums" >&2
    exit 1
  fi
}

verify_checksum() {
  local asset="$1"
  local archive="$2"
  local checksums="$3"

  # GoReleaser checksums.txt: "<hex>  <filename>" (two spaces)
  local expected
  expected="$(awk -v asset="${asset}" '
    $2 == asset { print $1; exit }
  ' "${checksums}")"

  if [[ -z "${expected}" ]]; then
    echo "checksum entry for ${asset} not found in checksums.txt" >&2
    exit 1
  fi

  local actual
  actual="$(sha256_file "${archive}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "checksum mismatch for ${asset}" >&2
    echo "  expected: ${expected}" >&2
    echo "  actual:   ${actual}" >&2
    exit 1
  fi
  echo "Checksum OK (${asset})"
}

if [[ -z "${VERSION}" ]]; then
  RELEASE_JSON_FILE="$(mktemp)"
  if github_curl "https://api.github.com/repos/${REPO}/releases/latest" "${RELEASE_JSON_FILE}"; then
    VERSION="$(sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "${RELEASE_JSON_FILE}" | head -n1)"
  fi
  rm -f "${RELEASE_JSON_FILE}"
fi

# Normalize: allow VERSION=v1.0.0 or 1.0.0
VERSION="${VERSION#v}"

if [[ -z "${VERSION}" || "${VERSION}" == "null" ]]; then
  cat >&2 <<'EOF'
No GitHub Release found yet.

Until a v* tag is published:
  git clone https://github.com/cozyGarage/sentielflow
  cd sentielflow && make build
  # or: docker build -t sentinelflow/sentinelflow:local .
EOF
  exit 1
fi

OS="$(detect_os)"
ARCH="$(detect_arch)"
EXT="tar.gz"
[[ "${OS}" == "windows" ]] && EXT="zip"

ASSET="sentinelflow_${VERSION}_${OS}_${ARCH}.${EXT}"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Downloading ${URL}"
if ! github_curl "${URL}" "${TMP}/${ASSET}"; then
  echo "Download failed. Check that release v${VERSION} exists and includes ${ASSET}." >&2
  exit 1
fi

if [[ "${SKIP_CHECKSUM}" != "1" ]]; then
  echo "Downloading ${CHECKSUMS_URL}"
  if ! github_curl "${CHECKSUMS_URL}" "${TMP}/checksums.txt"; then
    echo "Failed to download checksums.txt for v${VERSION}." >&2
    echo "Set SKIP_CHECKSUM=1 to bypass (not recommended)." >&2
    exit 1
  fi
  verify_checksum "${ASSET}" "${TMP}/${ASSET}" "${TMP}/checksums.txt"
  if [[ "${VERIFY_SIGNATURE:-0}" == "1" ]]; then
    github_curl "https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt.sig" "${TMP}/checksums.txt.sig" || true
    github_curl "https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt.pem" "${TMP}/checksums.txt.pem" || true
    verify_cosign "${TMP}/checksums.txt"
  fi
fi

mkdir -p "${INSTALL_DIR}"
if [[ "${EXT}" == "zip" ]]; then
  if command -v unzip >/dev/null 2>&1; then
    unzip -qo "${TMP}/${ASSET}" -d "${TMP}/extract"
  else
    echo "unzip is required for Windows archives" >&2
    exit 1
  fi
else
  mkdir -p "${TMP}/extract"
  tar -xzf "${TMP}/${ASSET}" -C "${TMP}/extract"
fi

BIN_SRC="$(find "${TMP}/extract" -type f -name 'sentinelflow' | head -n1)"
if [[ -z "${BIN_SRC}" ]]; then
  BIN_SRC="$(find "${TMP}/extract" -type f -name 'sentinelflow.exe' | head -n1)"
fi
if [[ -z "${BIN_SRC}" ]]; then
  echo "sentinelflow binary not found in archive" >&2
  exit 1
fi

BIN_NAME="$(basename "${BIN_SRC}")"
install -m 0755 "${BIN_SRC}" "${INSTALL_DIR}/${BIN_NAME}"
echo "Installed ${INSTALL_DIR}/${BIN_NAME}"
"${INSTALL_DIR}/${BIN_NAME}" version || true
