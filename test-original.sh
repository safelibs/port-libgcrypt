#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
implementation=original

usage() {
  cat <<'EOF'
Usage: test-original.sh [--implementation original|safe]
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --implementation)
      implementation="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done

case "${implementation}" in
  original|safe)
    ;;
  *)
    echo "unsupported implementation: ${implementation}" >&2
    exit 1
    ;;
esac

if [[ ! -f "$repo_root/dependents.json" ]]; then
  echo "missing $repo_root/dependents.json" >&2
  exit 1
fi

if [[ ! -d "$repo_root/original/libgcrypt20-1.10.3" ]]; then
  echo "missing $repo_root/original/libgcrypt20-1.10.3" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

docker run --rm -i \
  -e DEBIAN_FRONTEND=noninteractive \
  -e IMPLEMENTATION="${implementation}" \
  -v "$repo_root:/work:ro" \
  -w /tmp \
  ubuntu:24.04 \
  bash -s <<'DOCKER_SCRIPT'
set -euo pipefail

IMPLEMENTATION="${IMPLEMENTATION:-original}"
REPO_DIR=/work
SAFE_WORKTREE=/tmp/safe-worktree
log_dir=/tmp/test-original-logs
mkdir -p "$log_dir"

run_logged() {
  local label=$1
  local log=$2
  shift 2

  printf '==> %s\n' "$label"
  if ! "$@" >"$log" 2>&1; then
    printf 'FAILED: %s\n' "$label" >&2
    tail -n 200 "$log" >&2 || true
    exit 1
  fi
}

run_step() {
  local label=$1
  local func=$2
  local log="$log_dir/$func.log"

  printf '==> %s\n' "$label"
  if ! "$func" >"$log" 2>&1; then
    printf 'FAILED: %s\n' "$label" >&2
    tail -n 200 "$log" >&2 || true
    exit 1
  fi
}

capture_step() {
  local label=$1
  local log=$2
  local var_name=$3
  shift 3

  local output
  printf '==> %s\n' "$label"
  if ! output=$("$@" 2>"$log"); then
    printf 'FAILED: %s\n' "$label" >&2
    tail -n 200 "$log" >&2 || true
    exit 1
  fi
  printf -v "$var_name" '%s' "$output"
}

fetch_source_dir() {
  local pkg=$1
  local dest="/tmp/dependent-sources/$pkg"
  local dir

  rm -rf "$dest"
  mkdir -p "$dest"
  (
    cd "$dest"
    apt-get source "$pkg" >/dev/null
  )

  dir=$(find "$dest" -mindepth 1 -maxdepth 1 -type d | head -n 1)
  if [[ -z "$dir" ]]; then
    echo "failed to locate unpacked source for $pkg" >&2
    return 1
  fi
  printf '%s\n' "$dir"
}

assert_uses_built_libgcrypt() {
  local name=$1
  shift
  local trace loaded real

  trace=$(env \
    LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
    SAFE_SYSTEM_LIBGCRYPT_PATH="${SAFE_SYSTEM_LIBGCRYPT_PATH:-}" \
    LD_TRACE_LOADED_OBJECTS=1 \
    "$@" 2>/dev/null || true)
  loaded=$(awk '/libgcrypt\.so\.20/ {print $3; exit}' <<<"$trace")
  if [[ -z "$loaded" ]]; then
    printf 'built libgcrypt was not used by %s\n' "$name" >&2
    printf '%s\n' "$trace" >&2
    return 1
  fi

  real=$(readlink -f "$loaded")
  if [[ "$real" != "$LIBGCRYPT_EXPECTED_REALPATH" ]]; then
    printf 'unexpected libgcrypt path for %s: %s (expected %s)\n' \
      "$name" "$real" "$LIBGCRYPT_EXPECTED_REALPATH" >&2
    printf '%s\n' "$trace" >&2
    return 1
  fi
}

validate_dependents_json() {
  python3 - "${REPO_DIR}/dependents.json" <<'PY'
import json
from pathlib import Path
import sys

expected = {
    "libapt-pkg6.0t64",
    "gpg",
    "gnome-keyring",
    "libssh-gcrypt-4",
    "libxmlsec1t64-gcrypt",
    "munge",
    "aircrack-ng",
    "wireshark-common",
}

data = json.loads(Path(sys.argv[1]).read_text())
actual = {entry["binary_package"] for entry in data["dependents"]}
if actual != expected:
    raise SystemExit(f"dependents.json drifted: {sorted(actual)} != {sorted(expected)}")
PY
}

copy_committed_repo_inputs() {
  rm -rf "$SAFE_WORKTREE"
  mkdir -p "$SAFE_WORKTREE"
  git -C /work archive --format=tar HEAD | tar -xf - -C "$SAFE_WORKTREE"
  REPO_DIR="$SAFE_WORKTREE"
}

stash_upstream_libgcrypt() {
  local system_lib real_lib base

  system_lib=$(ldconfig -p | awk '/libgcrypt\.so\.20 .*=>/ {print $NF; exit}')
  [[ -n "$system_lib" ]] || {
    echo "failed to locate system libgcrypt.so.20" >&2
    return 1
  }

  real_lib=$(readlink -f "$system_lib")
  base=$(basename "$real_lib")
  mkdir -p /opt/libgcrypt-upstream
  cp "$real_lib" "/opt/libgcrypt-upstream/$base"
  ln -sfn "$base" /opt/libgcrypt-upstream/libgcrypt.so.20
  export SAFE_SYSTEM_LIBGCRYPT_PATH=/opt/libgcrypt-upstream/libgcrypt.so.20
}

build_safe_debs() {
  local cargo_home
  cargo_home=$(mktemp -d)
  trap 'rm -rf "$cargo_home"' RETURN

  (
    cd "$REPO_DIR"
    CARGO_HOME="$cargo_home" CARGO_NET_OFFLINE=true safe/scripts/build-debs.sh
  )
}

install_safe_debs() {
  local multiarch

  stash_upstream_libgcrypt
  dpkg -i "$REPO_DIR"/safe/dist/libgcrypt20_*.deb "$REPO_DIR"/safe/dist/libgcrypt20-dev_*.deb

  multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
  export LIBGCRYPT_EXPECTED_REALPATH
  LIBGCRYPT_EXPECTED_REALPATH="$(readlink -f "/usr/lib/${multiarch}/libgcrypt.so.20")"
  export LD_LIBRARY_PATH="/usr/lib/${multiarch}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export PKG_CONFIG_PATH="/usr/lib/${multiarch}/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
}

run_safe_helper_smoke() {
  (
    cd "$REPO_DIR"
    SAFE_SYSTEM_LIBGCRYPT_PATH="${SAFE_SYSTEM_LIBGCRYPT_PATH}" \
      safe/scripts/check-installed-tools.sh --dist safe/dist
  )
}

setup_original_under_test() {
  local build_dir=/tmp/build-libgcrypt

  export LIBGCRYPT_PREFIX=/opt/libgcrypt-under-test
  run_logged "configure original libgcrypt" "$log_dir/libgcrypt-configure.log" \
    bash -lc "rm -rf '$build_dir' '$LIBGCRYPT_PREFIX' && mkdir -p '$build_dir' && cd '$build_dir' && /work/original/libgcrypt20-1.10.3/configure --prefix='$LIBGCRYPT_PREFIX'"
  run_logged "build original libgcrypt" "$log_dir/libgcrypt-make.log" \
    bash -lc "cd '$build_dir' && make -j\"\$(nproc)\""
  run_logged "install original libgcrypt" "$log_dir/libgcrypt-install.log" \
    bash -lc "cd '$build_dir' && make install"

  export LIBGCRYPT_EXPECTED_REALPATH
  LIBGCRYPT_EXPECTED_REALPATH="$(readlink -f "$LIBGCRYPT_PREFIX/lib/libgcrypt.so.20")"
  export LD_LIBRARY_PATH="$LIBGCRYPT_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export PKG_CONFIG_PATH="$LIBGCRYPT_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
}

test_apt_libapt_pkg() {
  cat >/tmp/apt-hashes-test.cpp <<'SRC'
#include <apt-pkg/hashes.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

int main() {
    const std::string path = "/tmp/apt-hashes-input.txt";
    std::ofstream(path) << "apt libgcrypt hash path\n";

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    Hashes hashes(Hashes::SHA256SUM | Hashes::SHA1SUM);
    if (!hashes.AddFD(fd, Hashes::UntilEOF)) {
        close(fd);
        return 2;
    }
    close(fd);

    std::cout << hashes.GetHashString(Hashes::SHA256SUM).HashValue() << "\n";
    std::cout << hashes.GetHashString(Hashes::SHA1SUM).HashValue() << "\n";
    return 0;
}
SRC

  c++ -std=c++17 -O2 -o /tmp/apt-hashes-test /tmp/apt-hashes-test.cpp $(pkg-config --cflags --libs apt-pkg)
  assert_uses_built_libgcrypt "libapt-pkg Hashes" /tmp/apt-hashes-test

  /tmp/apt-hashes-test > /tmp/apt-hashes.out
  sha256sum /tmp/apt-hashes-input.txt | cut -d' ' -f1 > /tmp/apt-sha256.out
  sha1sum /tmp/apt-hashes-input.txt | cut -d' ' -f1 > /tmp/apt-sha1.out

  head -n 1 /tmp/apt-hashes.out | diff -u - /tmp/apt-sha256.out
  sed -n '2p' /tmp/apt-hashes.out | diff -u - /tmp/apt-sha1.out
}

test_gpg() {
  assert_uses_built_libgcrypt "gpg" /usr/bin/gpg

  export GNUPGHOME=/tmp/gnupg-test
  rm -rf "$GNUPGHOME"
  mkdir -m 700 -p "$GNUPGHOME"

  cat >/tmp/gpg-batch <<'CFG'
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Gcrypt Test
Name-Email: gcrypt@example.com
Expire-Date: 0
CFG

  gpg --batch --generate-key /tmp/gpg-batch
  printf 'libgcrypt gpg test\n' > /tmp/message.txt
  gpg --batch --yes --armor --output /tmp/message.txt.asc --sign /tmp/message.txt
  gpg --batch --verify /tmp/message.txt.asc >/tmp/gpg-verify.log 2>&1
  gpg --batch --yes --trust-model always --armor \
    --recipient gcrypt@example.com \
    --output /tmp/message.txt.gpg \
    --encrypt /tmp/message.txt
  gpg --batch --yes --output /tmp/message.dec --decrypt /tmp/message.txt.gpg >/tmp/gpg-decrypt.log 2>&1

  cmp /tmp/message.txt /tmp/message.dec
  grep -q 'Good signature' /tmp/gpg-verify.log
  grep -q 'encrypted with rsa2048 key' /tmp/gpg-decrypt.log
}

test_gnome_keyring() {
  assert_uses_built_libgcrypt "gnome-keyring-daemon" /usr/bin/gnome-keyring-daemon

  (
    export HOME=/tmp/gnome-home
    rm -rf "$HOME"
    mkdir -p "$HOME"

    dbus-run-session -- bash -lc '
      set -euo pipefail
      export LD_LIBRARY_PATH='"'"$LD_LIBRARY_PATH"'"'
      export SAFE_SYSTEM_LIBGCRYPT_PATH='"'"${SAFE_SYSTEM_LIBGCRYPT_PATH:-}"'"'
      export HOME='"'"$HOME"'"'

      eval "$(gnome-keyring-daemon --start --components=secrets)"
      printf %s stored-secret |
        secret-tool store --collection=session --label="Test Secret" service demo account alice

      value=$(secret-tool lookup service demo account alice)
      test "$value" = stored-secret
    '
  )
}

test_libssh_gcrypt() {
  local sshd_pid=''
  cleanup() {
    if [[ -n "${sshd_pid:-}" ]]; then
      kill "$sshd_pid" 2>/dev/null || true
    fi
  }
  trap cleanup RETURN

  id -u sshuser >/dev/null 2>&1 || useradd -m -s /bin/bash sshuser
  printf 'sshuser:secretpw\n' | chpasswd

  cat >/tmp/libssh-test.c <<'SRC'
#include <libssh/libssh.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    ssh_session session = ssh_new();
    if (session == NULL) {
        return 1;
    }

    int port = 2222;
    ssh_options_set(session, SSH_OPTIONS_HOST, "127.0.0.1");
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, "sshuser");

    if (ssh_connect(session) != SSH_OK) {
        return 2;
    }
    if (ssh_userauth_password(session, NULL, "secretpw") != SSH_AUTH_SUCCESS) {
        return 3;
    }

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        return 4;
    }
    if (ssh_channel_open_session(channel) != SSH_OK) {
        return 5;
    }
    if (ssh_channel_request_exec(channel, "printf libssh-ok") != SSH_OK) {
        return 6;
    }

    char buffer[128];
    int n = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
    if (n < 0) {
        return 7;
    }
    buffer[n] = '\0';

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    return strcmp(buffer, "libssh-ok") == 0 ? 0 : 8;
}
SRC

  cc -O2 -o /tmp/libssh-test /tmp/libssh-test.c $(pkg-config --cflags --libs libssh)
  assert_uses_built_libgcrypt "libssh-gcrypt client" /tmp/libssh-test

  cat >/tmp/sshd_config_test <<'CFG'
Port 2222
ListenAddress 127.0.0.1
PasswordAuthentication yes
UsePAM no
ChallengeResponseAuthentication no
PidFile /tmp/sshd_test.pid
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp /usr/lib/openssh/sftp-server
CFG

  mkdir -p /run/sshd
  /usr/sbin/sshd -f /tmp/sshd_config_test
  sshd_pid=$(cat /tmp/sshd_test.pid)

  /tmp/libssh-test
}

test_xmlsec_gcrypt() {
  cat >/tmp/xmlsec-gcrypt-verify-rsa.c <<'SRC'
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlSecKeysMngrPtr mngr = NULL;

    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    if (xmlSecInit() < 0) {
        return 3;
    }
    if (xmlSecCheckVersion() != 1) {
        return 4;
    }
    if (xmlSecCryptoAppInit(NULL) < 0) {
        return 5;
    }
    if (xmlSecCryptoInit() < 0) {
        return 6;
    }

    mngr = xmlSecKeysMngrCreate();
    if (mngr == NULL) {
        return 7;
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        return 8;
    }

    doc = xmlParseFile(argv[1]);
    if (doc == NULL) {
        return 10;
    }
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if (node == NULL) {
        return 11;
    }

    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if (dsigCtx == NULL) {
        return 12;
    }
    if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        return 13;
    }
    if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
        return 14;
    }

    puts("xmlsec-gcrypt-rsa-verify-ok");

    xmlSecDSigCtxDestroy(dsigCtx);
    xmlFreeDoc(doc);
    xmlSecKeysMngrDestroy(mngr);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
    return 0;
}
SRC

  cc -O2 -o /tmp/xmlsec-gcrypt-verify-rsa \
    /tmp/xmlsec-gcrypt-verify-rsa.c \
    $(pkg-config --cflags --libs xmlsec1-gcrypt)

  assert_uses_built_libgcrypt "xmlsec1 gcrypt backend" /tmp/xmlsec-gcrypt-verify-rsa
  /tmp/xmlsec-gcrypt-verify-rsa \
    "$xmlsec_src/tests/merlin-xmldsig-twenty-three/signature-enveloping-rsa.xml" |
    grep -q 'xmlsec-gcrypt-rsa-verify-ok'
}

test_munge() {
  local munged_pid=''
  cleanup() {
    if [[ -n "${munged_pid:-}" ]]; then
      kill "$munged_pid" 2>/dev/null || true
    fi
  }
  trap cleanup RETURN

  assert_uses_built_libgcrypt "munged" /usr/sbin/munged

  mkdir -p /etc/munge /run/munge /var/lib/munge /var/log/munge
  chown -R munge:munge /etc/munge /run/munge /var/lib/munge /var/log/munge
  rm -f /run/munge/munged.pid /run/munge/munge.socket.2
  head -c 32 /dev/urandom > /etc/munge/munge.key
  chmod 0400 /etc/munge/munge.key
  chown munge:munge /etc/munge/munge.key

  runuser -u munge -- env \
    LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    SAFE_SYSTEM_LIBGCRYPT_PATH="${SAFE_SYSTEM_LIBGCRYPT_PATH:-}" \
    munged --pid-file /run/munge/munged.pid --socket /run/munge/munge.socket.2
  munged_pid=$(cat /run/munge/munged.pid)

  credential=$(munge -n)
  printf '%s\n' "$credential" | unmunge > /tmp/unmunge.out

  grep -q 'STATUS:          Success (0)' /tmp/unmunge.out
  grep -q 'CIPHER:          aes128 (4)' /tmp/unmunge.out
  grep -q 'MAC:             sha256 (5)' /tmp/unmunge.out
}

test_aircrack_ng() {
  assert_uses_built_libgcrypt "aircrack-ng" /usr/bin/aircrack-ng

  aircrack-ng \
    -w "$aircrack_src/test/password.lst" \
    -a 2 \
    -e linksys \
    -q \
    "$aircrack_src/test/wpa2-psk-linksys.cap" > /tmp/aircrack.out 2>&1

  grep -q 'KEY FOUND! \[ dictionary \]' /tmp/aircrack.out
}

test_wireshark() {
  assert_uses_built_libgcrypt "tshark" /usr/bin/tshark

  (
    export HOME=/tmp/wireshark-home
    rm -rf "$HOME"
    mkdir -p "$HOME/.config/wireshark"
    cp "$wireshark_src/test/config/80211_keys.tmpl" "$HOME/.config/wireshark/80211_keys"

    zcat "$wireshark_src/test/captures/wpa-test-decode.pcap.gz" > /tmp/wpa-test-decode.pcap
    HOME="$HOME" tshark \
      -o 'wlan.enable_decryption: TRUE' \
      -r /tmp/wpa-test-decode.pcap \
      -Y 'icmp.resp_to == 4263' > /tmp/tshark.out 2>/tmp/tshark.err

    grep -q 'Echo (ping) reply' /tmp/tshark.out
  )
}

base_packages=(
  aircrack-ng
  build-essential
  dbus
  dbus-user-session
  dbus-x11
  gnome-keyring
  gnupg
  libapt-pkg-dev
  libgpg-error-dev
  libsecret-tools
  libssh-gcrypt-dev
  libxmlsec1-dev
  munge
  openssh-server
  pkg-config
  python3
  texinfo
  tshark
  wireshark-common
)

safe_extra_packages=(
  autoconf
  automake
  cargo
  ca-certificates
  curl
  debhelper
  dpkg-dev
  fakeroot
  git
  libgmp-dev
  rustc
)

setup_modern_rust_toolchain() {
  local cargo_version
  cargo_version="$(cargo --version | awk '{print $2}')"
  if dpkg --compare-versions "${cargo_version}" ge 1.85; then
    return 0
  fi

  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
  export PATH="/root/.cargo/bin:${PATH}"
}

run_logged "apt update" "$log_dir/apt-update.log" apt-get update
if [[ "$IMPLEMENTATION" == "safe" ]]; then
  run_logged "install build and runtime dependencies" "$log_dir/apt-install.log" \
    apt-get install -y --no-install-recommends "${base_packages[@]}" "${safe_extra_packages[@]}"
else
  run_logged "install build and runtime dependencies" "$log_dir/apt-install.log" \
    apt-get install -y --no-install-recommends "${base_packages[@]}"
fi
run_logged "enable source repositories" "$log_dir/enable-deb-src.log" \
  bash -lc "sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources && apt-get update"

if [[ "$IMPLEMENTATION" == "safe" ]]; then
  run_step "copy committed repository inputs" copy_committed_repo_inputs
fi

if [[ "$IMPLEMENTATION" == "safe" ]]; then
  run_step "install modern Rust toolchain" setup_modern_rust_toolchain
fi

run_step "validate dependents.json coverage" validate_dependents_json
capture_step "fetch aircrack-ng source" "$log_dir/fetch-aircrack.log" aircrack_src fetch_source_dir aircrack-ng
capture_step "fetch wireshark source" "$log_dir/fetch-wireshark.log" wireshark_src fetch_source_dir wireshark
capture_step "fetch xmlsec1 source" "$log_dir/fetch-xmlsec.log" xmlsec_src fetch_source_dir xmlsec1

if [[ "$IMPLEMENTATION" == "safe" ]]; then
  run_step "build safe Debian packages" build_safe_debs
  run_step "install safe Debian packages" install_safe_debs
  run_step "smoke installed helper tools" run_safe_helper_smoke
else
  setup_original_under_test
fi

run_step "test APT / libapt-pkg hashing" test_apt_libapt_pkg
run_step "test GnuPG signing and encryption" test_gpg
run_step "test GNOME Keyring secret service" test_gnome_keyring
run_step "test libssh gcrypt handshake" test_libssh_gcrypt
run_step "test xmlsec1 gcrypt backend" test_xmlsec_gcrypt
run_step "test MUNGE credential encode/decode" test_munge
run_step "test aircrack-ng WPA cracking sample" test_aircrack_ng
run_step "test Wireshark WPA decryption" test_wireshark

printf '\nAll dependent-software checks passed against the %s libgcrypt build.\n' "$IMPLEMENTATION"
DOCKER_SCRIPT
