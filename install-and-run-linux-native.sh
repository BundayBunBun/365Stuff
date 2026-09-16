#!/usr/bin/env bash
set -euo pipefail

# Native Linux runner (Python, no PowerShell).
# Usage:
#   ./install-and-run-linux-native.sh
#   ./install-and-run-linux-native.sh --output ./output --lookback-days 180 --graph-profile beta

OUTPUT_DIR="./output"
LOOKBACK_DAYS="90"
SKIP_GROUP_EXPANSION="false"
INCLUDE_DISABLED_SPS="false"
TENANT="organizations"
GRAPH_PROFILE="beta"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --lookback-days)
      LOOKBACK_DAYS="$2"
      shift 2
      ;;
    --skip-group-expansion)
      SKIP_GROUP_EXPANSION="true"
      shift
      ;;
    --include-disabled-service-principals)
      INCLUDE_DISABLED_SPS="true"
      shift
      ;;
    --tenant)
      TENANT="$2"
      shift 2
      ;;
    --graph-profile)
      GRAPH_PROFILE="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'HELP'
Usage:
  ./install-and-run-linux-native.sh [options]

Options:
  --output <dir>                                Output directory (default: ./output)
  --lookback-days <days>                        App/user activity lookback in days (default: 90)
  --skip-group-expansion                        Do not expand users from assigned groups
  --include-disabled-service-principals         Include disabled enterprise apps
  --tenant <tenant-id-or-domain>                Tenant selector (default: organizations)
  --graph-profile <v1.0|beta>                   Graph profile (default: beta)
  -h, --help                                    Show this help
HELP
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "./m365_enterprise_app_inventory.py" ]]; then
  echo "m365_enterprise_app_inventory.py not found in current directory." >&2
  echo "Run this from the repository root." >&2
  exit 1
fi

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if [[ $EUID -eq 0 ]]; then
  SUDO=""
elif have_cmd sudo; then
  SUDO="sudo"
else
  SUDO=""
fi

if ! have_cmd python3; then
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
  fi

  case "${ID:-}" in
    ubuntu|debian|linuxmint|pop|neon|zorin)
      $SUDO apt-get update
      $SUDO apt-get install -y python3 python3-venv python3-pip
      ;;
    rhel|centos|rocky|almalinux|fedora)
      if have_cmd dnf; then
        $SUDO dnf install -y python3 python3-pip
      elif have_cmd yum; then
        $SUDO yum install -y python3 python3-pip
      else
        echo "Could not install python3 automatically. Install python3 and pip manually." >&2
        exit 1
      fi
      ;;
    *)
      echo "Unsupported distro for automatic Python install. Install python3 + pip manually." >&2
      exit 1
      ;;
  esac
fi

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-native.txt

PY_ARGS=(
  --output-folder "$OUTPUT_DIR"
  --lookback-days "$LOOKBACK_DAYS"
  --tenant "$TENANT"
  --graph-profile "$GRAPH_PROFILE"
)

if [[ "$SKIP_GROUP_EXPANSION" == "true" ]]; then
  PY_ARGS+=(--skip-group-expansion)
fi

if [[ "$INCLUDE_DISABLED_SPS" == "true" ]]; then
  PY_ARGS+=(--include-disabled-service-principals)
fi

python ./m365_enterprise_app_inventory.py "${PY_ARGS[@]}"

echo "Done. Check ${OUTPUT_DIR} for CSV, JSON, and HTML outputs."
