#!/usr/bin/env bash
set -euo pipefail

# Installs PowerShell + Microsoft Graph module, then runs the read-only inventory script.
# Usage:
#   ./install-and-run-linux.sh
#   ./install-and-run-linux.sh --output ./output --lookback-days 180 --skip-group-expansion

OUTPUT_DIR="./output"
LOOKBACK_DAYS="90"
USE_BETA="false"
SKIP_GROUP_EXPANSION="false"
INCLUDE_DISABLED_SPS="false"
USE_DEVICE_CODE="true"

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
    --use-beta)
      USE_BETA="true"
      shift
      ;;
    --skip-group-expansion)
      SKIP_GROUP_EXPANSION="true"
      shift
      ;;
    --include-disabled-service-principals)
      INCLUDE_DISABLED_SPS="true"
      shift
      ;;
    --no-device-code)
      USE_DEVICE_CODE="false"
      shift
      ;;
    -h|--help)
      cat <<'HELP'
Usage:
  ./install-and-run-linux.sh [options]

Options:
  --output <dir>                                Output directory (default: ./output)
  --lookback-days <days>                        App/user activity lookback in days (default: 90)
  --use-beta                                    Use Microsoft Graph beta profile
  --skip-group-expansion                        Do not expand users from assigned groups
  --include-disabled-service-principals         Include disabled enterprise apps
  --no-device-code                              Use interactive auth instead of device code
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

if [[ ! -f "./Get-M365EnterpriseAppInventory.ps1" ]]; then
  echo "Get-M365EnterpriseAppInventory.ps1 not found in current directory." >&2
  echo "Run this from the repository root." >&2
  exit 1
fi

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_powershell_if_missing() {
  if have_cmd pwsh; then
    echo "PowerShell already installed: $(pwsh --version)"
    return
  fi

  if [[ $EUID -eq 0 ]]; then
    SUDO=""
  elif have_cmd sudo; then
    SUDO="sudo"
  else
    echo "pwsh is missing and sudo is not available. Install PowerShell manually and retry." >&2
    exit 1
  fi

  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
  else
    echo "/etc/os-release not found. Install PowerShell manually and retry." >&2
    exit 1
  fi

  echo "Installing PowerShell for distro: ${ID:-unknown}"

  case "${ID:-}" in
    ubuntu|debian)
      $SUDO apt-get update
      $SUDO apt-get install -y wget apt-transport-https software-properties-common gnupg
      wget -q https://packages.microsoft.com/config/${ID}/${VERSION_ID}/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
      $SUDO dpkg -i /tmp/packages-microsoft-prod.deb
      rm -f /tmp/packages-microsoft-prod.deb
      $SUDO apt-get update
      $SUDO apt-get install -y powershell
      ;;
    rhel|centos|rocky|almalinux|fedora)
      if have_cmd dnf; then
        $SUDO rpm --import https://packages.microsoft.com/keys/microsoft.asc
        $SUDO curl -fsSL -o /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/9/prod.repo
        $SUDO dnf install -y powershell
      elif have_cmd yum; then
        $SUDO rpm --import https://packages.microsoft.com/keys/microsoft.asc
        $SUDO curl -fsSL -o /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/9/prod.repo
        $SUDO yum install -y powershell
      else
        echo "No supported package manager found. Install PowerShell manually." >&2
        exit 1
      fi
      ;;
    *)
      echo "Unsupported distro for automatic PowerShell install: ${ID:-unknown}" >&2
      echo "Install PowerShell manually: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux" >&2
      exit 1
      ;;
  esac
}

install_graph_module() {
  echo "Installing/updating Microsoft.Graph PowerShell module for current user..."
  pwsh -NoLogo -NoProfile -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber"
}

run_inventory() {
  local ps_args=(
    "-OutputFolder" "$OUTPUT_DIR"
    "-SignInLookbackDays" "$LOOKBACK_DAYS"
  )

  if [[ "$USE_BETA" == "true" ]]; then
    ps_args+=("-UseBetaProfile")
  fi

  if [[ "$SKIP_GROUP_EXPANSION" == "true" ]]; then
    ps_args+=("-SkipGroupMemberExpansion")
  fi

  if [[ "$INCLUDE_DISABLED_SPS" == "true" ]]; then
    ps_args+=("-IncludeDisabledServicePrincipals")
  fi

  if [[ "$USE_DEVICE_CODE" == "true" ]]; then
    ps_args+=("-UseDeviceCode")
  fi

  echo "Running inventory script..."
  pwsh -NoLogo -NoProfile -File "./Get-M365EnterpriseAppInventory.ps1" "${ps_args[@]}"
}

install_powershell_if_missing
install_graph_module
run_inventory

echo "Done. Check ${OUTPUT_DIR} for CSV, JSON, and HTML outputs."
