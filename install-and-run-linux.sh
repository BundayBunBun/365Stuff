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

ensure_pwsh_on_path() {
  if have_cmd pwsh; then
    return 0
  fi

  if [[ -x "$HOME/.local/bin/pwsh" ]]; then
    export PATH="$HOME/.local/bin:$PATH"
    return 0
  fi

  return 1
}

install_powershell_portable() {
  local release_json asset_url archive_file install_root

  echo "Attempting portable PowerShell install (no distro package required)..."

  release_json="$(curl -fsSL https://api.github.com/repos/PowerShell/PowerShell/releases/latest)" || {
    echo "Unable to query latest PowerShell release metadata from GitHub." >&2
    return 1
  }

  asset_url="$(printf '%s' "$release_json" | grep -Eo 'https://[^\"]+powershell-[0-9.]+-linux-x64\.tar\.gz' | head -n 1)"

  if [[ -z "$asset_url" ]]; then
    echo "Could not find a linux-x64 PowerShell release asset." >&2
    return 1
  fi

  archive_file="/tmp/powershell-linux-x64.tar.gz"
  install_root="$HOME/.local/powershell"

  mkdir -p "$install_root"
  curl -fsSL "$asset_url" -o "$archive_file"
  tar -xzf "$archive_file" -C "$install_root"
  chmod +x "$install_root/pwsh"

  mkdir -p "$HOME/.local/bin"
  ln -sf "$install_root/pwsh" "$HOME/.local/bin/pwsh"
  export PATH="$HOME/.local/bin:$PATH"

  if ensure_pwsh_on_path; then
    echo "Portable PowerShell installed at $HOME/.local/powershell"
    return 0
  fi

  return 1
}

install_powershell_via_snap() {
  if ! have_cmd snap; then
    return 1
  fi

  if [[ $EUID -eq 0 ]]; then
    SNAP_SUDO=""
  elif have_cmd sudo; then
    SNAP_SUDO="sudo"
  else
    echo "snap is available but sudo is required to install system snaps." >&2
    return 1
  fi

  echo "Attempting PowerShell install via snap..."
  $SNAP_SUDO snap install powershell --classic || return 1

  ensure_pwsh_on_path
}

first_working_url() {
  for url in "$@"; do
    if curl -fsSI "$url" >/dev/null 2>&1; then
      echo "$url"
      return 0
    fi
  done
  return 1
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
      $SUDO apt-get install -y curl wget apt-transport-https software-properties-common gnupg ca-certificates

      ver="${VERSION_ID//\"/}"
      major="${ver%%.*}"
      base_id="${ID:-ubuntu}"

      repo_candidates=(
        "https://packages.microsoft.com/config/${base_id}/${ver}/packages-microsoft-prod.deb"
      )

      if [[ "$base_id" == "ubuntu" ]]; then
        repo_candidates+=(
          "https://packages.microsoft.com/config/ubuntu/${major}.04/packages-microsoft-prod.deb"
          "https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb"
          "https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb"
          "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
        )
      else
        repo_candidates+=(
          "https://packages.microsoft.com/config/debian/${major}/packages-microsoft-prod.deb"
          "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb"
          "https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb"
        )
      fi

      repo_url="$(first_working_url "${repo_candidates[@]}")" || {
        echo "Could not locate a compatible Microsoft package repo bootstrap for ${base_id} ${ver}." >&2
        echo "Install guide: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux" >&2
        exit 1
      }

      echo "Using Microsoft repo bootstrap: ${repo_url}"
      wget -q "$repo_url" -O /tmp/packages-microsoft-prod.deb
      $SUDO dpkg -i /tmp/packages-microsoft-prod.deb
      rm -f /tmp/packages-microsoft-prod.deb

      $SUDO apt-get update

      if apt-cache show powershell >/dev/null 2>&1; then
        $SUDO apt-get install -y powershell
      elif apt-cache show powershell-lts >/dev/null 2>&1; then
        echo "Package 'powershell' not found, installing 'powershell-lts' instead."
        $SUDO apt-get install -y powershell-lts
      else
        echo "Neither 'powershell' nor 'powershell-lts' were found after configuring the Microsoft repo."
        if ! install_powershell_via_snap; then
          if ! install_powershell_portable; then
            echo "Install guide: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux" >&2
            exit 1
          fi
        fi
      fi
      ;;
    linuxmint|pop|neon|zorin)
      $SUDO apt-get update
      $SUDO apt-get install -y curl wget apt-transport-https software-properties-common gnupg ca-certificates

      ver="${VERSION_ID//\"/}"
      repo_url="$(first_working_url \
        "https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb" \
        "https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb" \
        "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb")" || {
        echo "Could not locate a compatible Ubuntu-based Microsoft package repo bootstrap for ${ID} ${ver}." >&2
        echo "Install guide: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux" >&2
        exit 1
      }

      echo "Using Microsoft repo bootstrap: ${repo_url}"
      wget -q "$repo_url" -O /tmp/packages-microsoft-prod.deb
      $SUDO dpkg -i /tmp/packages-microsoft-prod.deb
      rm -f /tmp/packages-microsoft-prod.deb

      $SUDO apt-get update

      if apt-cache show powershell >/dev/null 2>&1; then
        $SUDO apt-get install -y powershell
      elif apt-cache show powershell-lts >/dev/null 2>&1; then
        echo "Package 'powershell' not found, installing 'powershell-lts' instead."
        $SUDO apt-get install -y powershell-lts
      else
        echo "Neither 'powershell' nor 'powershell-lts' were found after configuring the Microsoft repo."
        if ! install_powershell_via_snap; then
          if ! install_powershell_portable; then
            echo "Install guide: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux" >&2
            exit 1
          fi
        fi
      fi
      ;;
    rhel|centos|rocky|almalinux|fedora)
      if have_cmd dnf; then
        $SUDO rpm --import https://packages.microsoft.com/keys/microsoft.asc
        $SUDO curl -fsSL -o /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/9/prod.repo
        if ! $SUDO dnf install -y powershell; then
          echo "Could not install powershell via dnf. Trying portable fallback."
          install_powershell_portable || exit 1
        fi
      elif have_cmd yum; then
        $SUDO rpm --import https://packages.microsoft.com/keys/microsoft.asc
        $SUDO curl -fsSL -o /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/9/prod.repo
        if ! $SUDO yum install -y powershell; then
          echo "Could not install powershell via yum. Trying portable fallback."
          install_powershell_portable || exit 1
        fi
      else
        echo "No supported package manager found. Install PowerShell manually." >&2
        exit 1
      fi
      ;;
    *)
      echo "Unsupported distro for automatic PowerShell install: ${ID:-unknown}" >&2
      echo "Trying portable fallback install..."
      install_powershell_portable || {
        echo "Install PowerShell manually: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux" >&2
        exit 1
      }
      ;;
  esac

  ensure_pwsh_on_path || {
    echo "PowerShell installation did not result in a usable 'pwsh' command." >&2
    exit 1
  }
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
