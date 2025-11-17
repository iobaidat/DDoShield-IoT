#!/usr/bin/env bash
# Install Docker, Docker Buildx, and ns-3 (plus requirements).
# Quiet by default; pass -v or --verbose for step-by-step logs.

set -Eeuo pipefail

# --------------------------- CLI & Logging ---------------------------
usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  -v, --verbose                 Verbose output
      --no-ns3                  Skip ns-3 install/build
      --no-docker               Skip Docker install
      --no-buildx               Skip Docker Buildx install/check
      --no-docker-ipv6          Do NOT write /etc/docker/daemon.json IPv6 config
      --ns3-test                Build & run the simple ns-3 "first" example
      --ns3-only                Only install/build ns-3
      --docker-only             Only install Docker + Buildx

  ns-3 controls:
      --ns3-version V           Set ns-3 version (e.g. 3.45 or 3.46.1).
                                If not provided and network/ns3_version is
                                missing/empty, the latest release is
                                auto-detected.
      --ns3-profile P           Build profile: optimized (default) or debug
      --ns3-configure-only      Only ensure the right ns-3 version is present,
                                then clean/re-configure/rebuild ns-3
                                (no Docker steps)
      --ns3-clean MODE          Cleaning mode before (re)config:
                                  auto (default)  -> "./ns3 clean" best-effort
                                  none            -> no clean
                                  clean           -> "./ns3 clean"
                                  distclean       -> "./ns3 distclean"
                                (ccache not touched)

Notes:
- ns-3 version is read from network/ns3_version (relative to this script),
  unless overridden via --ns3-version or auto-detected.
- For versions < 3.35: downloads ns-allinone-V and builds ns-V from within it.
- For versions >= 3.35: downloads ns-V only.
- After Docker install, a reboot is required to use Docker without sudo.
EOF
}

VERBOSE=0
DO_NS3=1
DO_DOCKER=1
DO_BUILDX=1
WRITE_DOCKER_IPV6=1
RUN_NS3_TEST=0
NS3_BUILD_PROFILE="optimized"     # optimized|debug
NS3_CONFIGURE_ONLY=0
NS3_CLEAN_MODE="auto"             # auto|none|clean|distclean
USER_NS3_VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; shift ;;
    --no-ns3) DO_NS3=0; shift ;;
    --no-docker) DO_DOCKER=0; shift ;;
    --no-buildx) DO_BUILDX=0; shift ;;
    --no-docker-ipv6) WRITE_DOCKER_IPV6=0; shift ;;
    --ns3-test) RUN_NS3_TEST=1; shift ;;
    --ns3-only) DO_NS3=1; DO_DOCKER=0; DO_BUILDX=0; shift ;;
    --docker-only) DO_NS3=0; DO_DOCKER=1; DO_BUILDX=1; shift ;;
    --ns3-version)
      USER_NS3_VERSION="${2:-}"
      shift 2
      ;;
    --ns3-profile)
      NS3_BUILD_PROFILE="${2:-optimized}"
      shift 2
      ;;
    --ns3-configure-only)
      NS3_CONFIGURE_ONLY=1
      DO_NS3=1
      DO_DOCKER=0
      DO_BUILDX=0
      shift
      ;;
    --ns3-clean)
      NS3_CLEAN_MODE="${2:-auto}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$NS3_BUILD_PROFILE" != "optimized" && "$NS3_BUILD_PROFILE" != "debug" ]]; then
  echo "[ERROR] --ns3-profile must be 'optimized' or 'debug'." >&2
  exit 2
fi

case "$NS3_CLEAN_MODE" in
  auto|none|clean|distclean) ;;
  *) echo "[ERROR] --ns3-clean must be auto|none|clean|distclean." >&2; exit 2 ;;
esac

C_GREEN="$(tput setaf 2 2>/dev/null || true)"
C_YEL="$(tput setaf 3 2>/dev/null || true)"
C_RED="$(tput setaf 1 2>/dev/null || true)"
C_DIM="$(tput dim 2>/dev/null || true)"
C_RST="$(tput sgr0 2>/dev/null || true)"

log() {
  if [[ "${VERBOSE:-0}" -eq 1 ]]; then
    echo "[$(date +%H:%M:%S)] $*"
  fi
}
info() { echo "${C_GREEN}[INFO]${C_RST} $*"; }
warn() { echo "${C_YEL}[WARN]${C_RST} $*"; }
fail() { echo "${C_RED}[ERROR]${C_RST} $*" >&2; exit 1; }

trap 'echo "'"${C_RED}[ERROR]${C_RST}"' install.sh failed at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
echo "${C_GREEN}[INFO]${C_RST} install.sh starting (verbose=${VERBOSE})"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)"
export DEBIAN_FRONTEND=noninteractive

as_root() {
  if [[ $EUID -ne 0 ]]; then
    sudo -H bash -lc "$1"
  else
    bash -lc "$1"
  fi
}

run() {
  local cmd="$1"; local label="${2:-$1}"
  log "Running: $cmd"
  if ! bash -lc "$cmd"; then
    fail "Failed: ${label}"
  fi
}

apt_update_retry() {
  local tries=3
  for i in $(seq 1 "$tries"); do
    if as_root "apt-get update -qq"; then
      return 0
    fi
    sleep 3
  done
  fail "apt-get update failed after ${tries} attempts"
}

apt_install() {
  [[ $# -eq 0 ]] && return 0
  local pkglist; pkglist="$(printf '%s ' "$@")"
  as_root "apt-get -o Dpkg::Use-Pty=0 install -y -qq ${pkglist}"
}

pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

quiet_remove_pkg() {
  local pkg="$1"
  if pkg_installed "$pkg"; then
    info "Removing '$pkg' (to avoid conflicts)..."
    as_root "apt-get remove -y -qq '$pkg' >/dev/null 2>&1 || true"
  else
    log "No '$pkg' installed; skipping removal."
  fi
}

command -v apt-get >/dev/null || fail "Debian/Ubuntu required (apt-get not found)."
command -v sudo >/dev/null || fail "sudo is required."

# Defaults for Docker group tracking
TARGET_USER="${SUDO_USER:-$USER}"
ADDED_DOCKER_GROUP=0
WAS_IN_DOCKER_PRE=0
EFFECTIVE_HAS_DOCKER=0

# --------------------------- Base packages ---------------------------
info "Updating package index & installing base tools..."
apt_update_retry
apt_install ca-certificates gnupg gnupg2 lsb-release software-properties-common apt-transport-https wget curl net-tools
apt_install g++ build-essential python3 python3-dev python3-setuptools python3-pip python-is-python3 \
            pkg-config cmake ninja-build git autoconf automake unzip p7zip-full libc6-dev libclang-dev llvm-dev libffi-dev

# --------------------------- ns-3 helpers ---------------------------

NS3_VERSION=""
ROOT_DIR=""
CORE_DIR=""
NS3_TOOL=""
NS3_TAR=""
NS3_URL=""

# A < B ? (version-aware)
version_lt() {
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" && "$1" != "$2" ]]
}

# Try to discover latest ns-3 version by scanning official sources for tags
# like "ns-3.46", then picking the highest via sort -V.
get_latest_ns3_version() {
  local html ver

  # 1) GitLab tags (canonical for ns-3-dev)
  if command -v curl >/dev/null 2>&1; then
    html=$(curl -fsSL "https://gitlab.com/nsnam/ns-3-dev/-/tags" || true)
  elif command -v wget >/dev/null 2>&1; then
    html=$(wget -qO- "https://gitlab.com/nsnam/ns-3-dev/-/tags" || true)
  else
    html=""
  fi

  if [[ -n "$html" ]]; then
    ver="$(
      printf '%s\n' "$html" \
      | grep -oE 'ns-3\.[0-9]+(\.[0-9]+)?' \
      | sed 's/^ns-//' \
      | sort -uV \
      | tail -n1
    )"
    if [[ -n "$ver" ]]; then
      printf '%s\n' "$ver"
      return 0
    fi
  fi

  # 2) GitLab releases (fallback)
  html=""
  if command -v curl >/dev/null 2>&1; then
    html=$(curl -fsSL "https://gitlab.com/nsnam/ns-3-dev/-/releases" || true)
  elif command -v wget >/dev/null 2>&1; then
    html=$(wget -qO- "https://gitlab.com/nsnam/ns-3-dev/-/releases" || true)
  fi

  if [[ -n "$html" ]]; then
    ver="$(
      printf '%s\n' "$html" \
      | grep -oE 'ns-3\.[0-9]+(\.[0-9]+)?' \
      | sed 's/^ns-//' \
      | sort -uV \
      | tail -n1
    )"
    if [[ -n "$ver" ]]; then
      printf '%s\n' "$ver"
      return 0
    fi
  fi

  # 3) ns-3 official releases page (fallback)
  html=""
  if command -v curl >/dev/null 2>&1; then
    html=$(curl -fsSL "https://www.nsnam.org/releases/" || true)
  elif command -v wget >/dev/null 2>&1; then
    html=$(wget -qO- "https://www.nsnam.org/releases/" || true)
  fi

  if [[ -n "$html" ]]; then
    ver="$(
      printf '%s\n' "$html" \
      | grep -oE 'ns-3\.[0-9]+(\.[0-9]+)?' \
      | sed 's/^ns-//' \
      | sort -uV \
      | tail -n1
    )"
    if [[ -n "$ver" ]]; then
      printf '%s\n' "$ver"
      return 0
    fi
  fi

  return 1
}

ns3_compute_layout() {
  local ver="$1"
  if version_lt "$ver" "3.45"; then
    # Legacy: ns-allinone-V with ns-V inside
    NS3_TAR="ns-allinone-${ver}.tar.bz2"
    NS3_URL="https://www.nsnam.org/releases/${NS3_TAR}"
    ROOT_DIR="ns-allinone-${ver}"
    CORE_DIR="${ROOT_DIR}/ns-${ver}"
  else
    # Modern: core-only tarball
    NS3_TAR="ns-${ver}.tar.bz2"
    NS3_URL="https://www.nsnam.org/releases/${NS3_TAR}"
    ROOT_DIR="ns-${ver}"
    CORE_DIR="${ROOT_DIR}"
  fi
  NS3_TOOL="${CORE_DIR}/ns3"
}

ns3_verify_remote_tar() {
  [[ -n "${NS3_URL:-}" ]] || return 1
  if command -v curl >/dev/null 2>&1; then
    curl -Isf "${NS3_URL}" >/dev/null 2>&1 && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q --spider "${NS3_URL}" >/dev/null 2>&1 && return 0
  fi
  return 1
}

ns3_resolve() {
  local ns3_file="${SCRIPT_DIR}/network/ns3_version"

  # 1) If user explicitly provided --ns3-version, that wins.
  if [[ -n "${USER_NS3_VERSION:-}" ]]; then
    NS3_VERSION="${USER_NS3_VERSION}"
  else
    # 2) Else, read from ns3_version file if present.
    if [[ -f "$ns3_file" ]]; then
      NS3_VERSION="$(tr -d ' \t\r\n' < "$ns3_file" || true)"
    fi

    # 3) If still empty, auto-detect latest from GitLab/nsnam.
    if [[ -z "${NS3_VERSION:-}" ]]; then
      info "No ns-3 version specified; detecting latest release..."
      local latest
      latest="$(get_latest_ns3_version || true)"
      if [[ -z "$latest" ]]; then
        fail "Could not determine latest ns-3 version. Use --ns3-version or create ${ns3_file}."
      fi
      NS3_VERSION="$latest"
      USER_NS3_VERSION="$NS3_VERSION"  # mark to persist after validation
      info "Auto-detected latest ns-3 version: ${NS3_VERSION}"
    fi
  fi

  [[ -n "${NS3_VERSION:-}" ]] || fail "ns-3 version is empty. Use --ns3-version or write to ${ns3_file}."

  ns3_compute_layout "${NS3_VERSION}"

  # If USER_NS3_VERSION set (explicit or auto), validate and write ns3_version.
  if [[ -n "${USER_NS3_VERSION:-}" ]]; then
    info "Checking ns-3 release for version ${NS3_VERSION} at ${NS3_URL}..."
    if ! ns3_verify_remote_tar; then
      fail "ns-3 version ${NS3_VERSION} not found at ${NS3_URL}. Aborting."
    fi
    mkdir -p "${SCRIPT_DIR}/network"
    printf '%s\n' "${NS3_VERSION}" > "${ns3_file}"
    log "Updated ${ns3_file} to ns-3 version ${NS3_VERSION}"
  fi

  info "Using ns-3 version ${NS3_VERSION} (layout root: ${ROOT_DIR}, core: ${CORE_DIR})"
}

ns3_fetch_if_missing() {
  pushd "${SCRIPT_DIR}/network" >/dev/null

  if [[ ! -d "$ROOT_DIR" ]]; then
    [[ -n "${NS3_TAR:-}" && -n "${NS3_URL:-}" ]] || fail "Internal error: NS3_TAR/NS3_URL not set."
    info "Downloading ns-3 ${NS3_VERSION} from ${NS3_URL} ..."
    if ! ns3_verify_remote_tar; then
      fail "ns-3 version ${NS3_VERSION} not available at ${NS3_URL}. Aborting."
    fi
    run "wget -q '${NS3_URL}' -O '${NS3_TAR}'" "Download ns-3 ${NS3_VERSION}"
    run "tar xjf '${NS3_TAR}'" "Extract ns-3 ${NS3_VERSION}"
    rm -f "${NS3_TAR}"
  else
    log "${ROOT_DIR} already present; skipping download"
  fi

  as_root "chmod -R +x '${ROOT_DIR}' || true"
  popd >/dev/null
}

ns3_clean() {
  [[ ! -d "${SCRIPT_DIR}/network/${CORE_DIR}" ]] && { log "ns-3 core dir not present; skipping clean"; return 0; }

  pushd "${SCRIPT_DIR}/network/${CORE_DIR}" >/dev/null
  case "$NS3_CLEAN_MODE" in
    none)
      log "Skipping ns-3 clean (mode=none)"
      ;;
    clean)
      run "./ns3 clean || true" "ns-3 clean"
      ;;
    distclean)
      run "./ns3 distclean || true" "ns-3 distclean"
      ;;
    auto)
      run "./ns3 clean || true" "ns-3 clean (auto)"
      ;;
  esac
  popd >/dev/null
}

ns3_configure_build() {
  pushd "${SCRIPT_DIR}/network/${CORE_DIR}" >/dev/null
  info "Configuring & building ns-3 via ./ns3 (profile=${NS3_BUILD_PROFILE})..."
  run "./ns3 configure --enable-sudo --disable-examples --disable-tests --disable-python --build-profile=${NS3_BUILD_PROFILE}" \
      "ns-3 configure"
  run "./ns3 build" "ns-3 build"

  if [[ $RUN_NS3_TEST -eq 1 ]]; then
    log "Running ns-3 sanity test (first.cc) via ./ns3 ..."
    cp "examples/tutorial/first.cc" "scratch/" || true
    run "./ns3 build" "ns-3 rebuild with scratch"
    run "./ns3 run first" "Run ns-3 'first' example"
    rm -f "scratch/first.cc" || true
  fi
  popd >/dev/null
}

# --------------------------- ns-3 (install or configure-only) -------
if [[ $DO_NS3 -eq 1 ]]; then
  info "Installing ns-3 toolchain & dependencies..."
  apt_install ccache gdb valgrind clang-format clang-tidy uncrustify
  apt_install qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools
  apt_install openmpi-bin openmpi-common openmpi-doc libopenmpi-dev
  apt_install mercurial doxygen graphviz imagemagick
  apt_install texlive texlive-extra-utils texlive-latex-extra texlive-font-utils dvipng latexmk
  apt_install python3-sphinx dia libeigen3-dev gsl-bin libgsl-dev libgslcblas0
  apt_install tcpdump sqlite3 libsqlite3-dev libgtk-3-dev
  apt_install vtun lxc uml-utilities ebtables bridge-utils
  apt_install libxml2 libxml2-dev libboost-all-dev
  apt_install gir1.2-goocanvas-2.0 python3-gi python3-gi-cairo python3-pygraphviz gir1.2-gtk-3.0 ipython3

  info "Ensuring ns-3 workspace matches requested/selected version..."
  run "mkdir -p '${SCRIPT_DIR}/network'"

  ns3_resolve
  ns3_fetch_if_missing
  ns3_resolve  # re-evaluate with ensured tree

  # Ensure ns3 tool is present
  if [[ -x "${SCRIPT_DIR}/network/${NS3_TOOL}" ]]; then
    NS3_TOOL="${SCRIPT_DIR}/network/${NS3_TOOL}"
  elif [[ -x "${SCRIPT_DIR}/network/${CORE_DIR}/ns3" ]]; then
    NS3_TOOL="${SCRIPT_DIR}/network/${CORE_DIR}/ns3"
  elif [[ -x "${NS3_TOOL}" ]]; then
    : # leave as-is
  else
    fail "Could not find executable 'ns3' tool under ${ROOT_DIR}"
  fi

  ns3_clean
  ns3_configure_build
fi

# --------------------------- Docker ---------------------------------
if [[ $DO_DOCKER -eq 1 ]]; then
  info "Installing Docker Engine..."
  quiet_remove_pkg containerd.io
  apt_update_retry
  apt_install docker.io

  info "Enabling & starting Docker..."
  as_root "systemctl enable --now docker || service docker start || true"

  info "Verifying Docker with hello-world (sudo run)..."
  run "sudo docker run --rm hello-world" "Docker hello-world"

  # Add current user to docker group
  TARGET_USER="${SUDO_USER:-$USER}"
  if [[ $EUID -eq 0 && -z "${SUDO_USER:-}" ]]; then
    TARGET_USER="$(getent passwd 1000 | cut -d: -f1 || true)"
    if [[ -z "$TARGET_USER" ]]; then
      TARGET_USER="$(logname 2>/dev/null || echo root)"
    fi
  fi

  # Ensure the docker group exists (idempotent)
  as_root "groupadd -f docker" || true

  ADDED_DOCKER_GROUP=0
  WAS_IN_DOCKER_PRE=0

  # Snapshot pre-state membership from /etc/group
  if id -nG "$TARGET_USER" | grep -qw docker 2>/dev/null; then
    WAS_IN_DOCKER_PRE=1
  else
    if as_root "usermod -aG docker $TARGET_USER"; then
      ADDED_DOCKER_GROUP=1
    fi
  fi

  # Does THIS shell/session already have the docker group effective?
  EFFECTIVE_HAS_DOCKER=0
  docker_gid="$(getent group docker | cut -d: -f3 || true)"
  if [[ -n "$docker_gid" ]]; then
    if [[ $EUID -ne 0 && -z "${SUDO_USER:-}" ]]; then
      # Running as the target user directly; check this process's group vector.
      if awk '/^Groups:/{for(i=2;i<=NF;i++) if ($i=='"$docker_gid"') f=1} END{exit !f}' /proc/$$/status; then
        EFFECTIVE_HAS_DOCKER=1
      fi
    else
      # Running under sudo/root. If we DID NOT just add the group,
      # check a fresh login shell for the target user to avoid over-prompting on re-runs.
      if [[ $ADDED_DOCKER_GROUP -eq 0 ]]; then
        if sudo -iu "$TARGET_USER" bash -lc "id -nG | grep -qw docker"; then
          EFFECTIVE_HAS_DOCKER=1
        fi
      fi
    fi
  fi


  if [[ $WRITE_DOCKER_IPV6 -eq 1 ]]; then
    info "Writing /etc/docker/daemon.json (IPv6 enabled; backup preserved)..."
    as_root 'mkdir -p /etc/docker; [[ -f /etc/docker/daemon.json ]] && cp /etc/docker/daemon.json /etc/docker/daemon.json.bak.$(date +%s) || true'
    as_root 'cat > /etc/docker/daemon.json <<JSON
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64",
  "experimental": true
}
JSON'
    as_root "systemctl restart docker || service docker restart || true"
  else
    warn "Skipping Docker IPv6 daemon.json as requested (--no-docker-ipv6)."
  fi
fi

# --------------------------- Buildx ---------------------------------
if [[ $DO_DOCKER -eq 1 && $DO_BUILDX -eq 1 ]]; then
  info "Installing Buildx prerequisites (qemu/binfmt)..."
  apt_update_retry
  apt_install qemu-user-static
  as_root "apt-get install -y -qq binfmt-support || true"

  if command -v qemu-x86_64-static >/dev/null 2>&1; then
    run "qemu-x86_64-static --version" "qemu multi-arch check"
  else
    warn "qemu-x86_64-static not found; cross-arch Docker emulation may be limited."
  fi

  info "Installing Docker Buildx..."
  apt_update_retry
  if as_root "apt-get install -y -qq docker-buildx"; then
    log "Installed package: docker-buildx"
  elif as_root "apt-get install -y -qq docker-buildx-plugin"; then
    log "Installed package: docker-buildx-plugin"
  else
    warn "Neither 'docker-buildx' nor 'docker-buildx-plugin' available from APT. Buildx may already be bundled with Docker. Continuing."
  fi

  as_root "systemctl restart docker || service docker restart || true"

  info "Checking Docker Buildx..."
  if ! docker buildx version >/dev/null 2>&1; then
    if ! docker buildx ls >/dev/null 2>&1; then
      warn "Docker Buildx not detected. If you need it, install from your distro or Docker’s official repo."
    fi
  fi
fi

# --------------------------- ddosim CLI symlink ---------------------------
if [[ $DO_DOCKER -eq 1 ]]; then
  CLI_NAME="ddosim"
  CLI_SRC="${SCRIPT_DIR}/${CLI_NAME}"
  CLI_DEST="/usr/local/bin/${CLI_NAME}"

  if [[ -x "${CLI_SRC}" ]]; then
    info "Installing/updating ${CLI_NAME} symlink at ${CLI_DEST}..."
    if [[ -e "${CLI_DEST}" && ! -L "${CLI_DEST}" ]]; then
      warn "${CLI_DEST} exists and is not a symlink; skipping ddosim symlink."
      warn "If this is an old install, remove or rename it manually."
    else
      as_root "ln -sf '${CLI_SRC}' '${CLI_DEST}'"
    fi
  else
    warn "Executable ${CLI_SRC} not found; skipping ddosim CLI symlink."
  fi
fi
# --------------------------- Summary --------------------------------
echo
info "Installation finished."

if [[ $DO_NS3 -eq 1 ]]; then
  local_mode="install/build"
  [[ $NS3_CONFIGURE_ONLY -eq 1 ]] && local_mode="configure-only"
  echo "${C_DIM}- ns-3:         version ${NS3_VERSION:-unknown} (./network/${ROOT_DIR:-?})${C_RST}"
  echo "${C_DIM}- ns-3 profile:  ${NS3_BUILD_PROFILE}${C_RST}"
  echo "${C_DIM}- ns-3 mode:     ${local_mode}${C_RST}"
  echo "${C_DIM}- ns-3 clean:    ${NS3_CLEAN_MODE}${C_RST}"
else
  echo "${C_DIM}- ns-3:         skipped${C_RST}"
fi

echo "${C_DIM}- Docker:       ${DO_DOCKER:+installed}${C_RST}"
echo "${C_DIM}- Buildx:       ${DO_BUILDX:+installed}${C_RST}"
[[ $DO_DOCKER -eq 1 && $WRITE_DOCKER_IPV6 -eq 1 ]] && \
  echo "${C_DIM}- Docker IPv6:  enabled (daemon.json written; backup saved)${C_RST}"
echo

# Require reboot if Docker was installed and current user can't use it yet
if [[ $DO_DOCKER -eq 1 && "$TARGET_USER" != "root" && ( $ADDED_DOCKER_GROUP -eq 1 || ( $WAS_IN_DOCKER_PRE -eq 1 && $EFFECTIVE_HAS_DOCKER -eq 0 ) ) ]]; then
  echo
  echo "${C_RED}[ACTION REQUIRED]${C_RST} Docker non-root access for '${TARGET_USER}' will be active after you re-login."
  echo "  ${C_GREEN}Log out and back in${C_RST}"
  if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "  WSL detected: run ${C_YEL}wsl.exe --shutdown${C_RST} then reopen your terminal."
  else
    echo "  On headless servers, a ${C_GREEN}reboot${C_RST} is simplest."
  fi
  echo
  if [[ "${AUTO_REBOOT:-0}" == "1" ]]; then
    info "Auto-reboot enabled — rebooting now..."
    as_root "reboot"
  fi
fi