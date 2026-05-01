#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMPLEMENTATION=
TAG=
MODE=
IN_IMAGE=0

usage() {
  cat <<'EOF'
Usage: run-dependent-image-tests.sh --implementation original|safe --tag IMAGE_TAG (--compile-probes|--all)
       run-dependent-image-tests.sh --in-image --implementation original|safe (--compile-probes|--all)
EOF
}

fail() {
  echo "run-dependent-image-tests: $*" >&2
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --implementation)
      IMPLEMENTATION="$2"
      shift 2
      ;;
    --tag)
      TAG="$2"
      shift 2
      ;;
    --compile-probes)
      MODE=compile-probes
      shift
      ;;
    --all)
      MODE=all
      shift
      ;;
    --in-image)
      IN_IMAGE=1
      shift
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

[[ "${IMPLEMENTATION}" == "original" || "${IMPLEMENTATION}" == "safe" ]] \
  || fail "--implementation must be original or safe"
[[ "${MODE}" == "compile-probes" || "${MODE}" == "all" ]] \
  || fail "one of --compile-probes or --all is required"

if [[ "${IN_IMAGE}" -eq 0 ]]; then
  [[ -n "${TAG}" ]] || fail "--tag is required outside the image"
  docker run --rm --privileged \
    -e "IMPLEMENTATION=${IMPLEMENTATION}" \
    "${TAG}" \
    bash -lc "set -euo pipefail; source /opt/libgcrypt-dependent/implementation.env; export IMPLEMENTATION LIBGCRYPT_EXPECTED_REALPATH PHASE_COMMIT PHASE_TAG; exec /opt/libgcrypt-dependent/safe/scripts/run-dependent-image-tests.sh --in-image --implementation ${IMPLEMENTATION} --${MODE}"
  exit 0
fi

cd "${REPO_DIR}"
source "${REPO_DIR}/implementation.env"
export IMPLEMENTATION LIBGCRYPT_EXPECTED_REALPATH PHASE_COMMIT PHASE_TAG

python3 "${REPO_DIR}/safe/tests/dependents/validate-installed-packages.py"

assert_uses_selected_libgcrypt() {
  local label=$1
  local binary=$2
  local trace loaded real

  trace="$(LD_TRACE_LOADED_OBJECTS=1 "${binary}" 2>/dev/null || true)"
  loaded="$(
    awk '
      /libgcrypt[.]so[.]20/ {
        for (i = 1; i <= NF; i++) {
          if ($i ~ "^/") {
            print $i
            exit
          }
        }
      }
    ' <<<"${trace}"
  )"
  [[ -n "${loaded}" ]] || {
    printf '%s\n' "${trace}" >&2
    fail "${label} did not load libgcrypt.so.20"
  }

  real="$(readlink -f "${loaded}")"
  [[ "${real}" == "${LIBGCRYPT_EXPECTED_REALPATH}" ]] || {
    printf '%s\n' "${trace}" >&2
    fail "${label} loaded ${real}, expected ${LIBGCRYPT_EXPECTED_REALPATH}"
  }
}

compile_apt_probe() {
  local source="${REPO_DIR}/safe/tests/dependents/probes/apt-hashes-test.cpp"
  c++ -std=c++17 -O2 -o /tmp/apt-hashes-test "${source}" \
    $(pkg-config --cflags --libs apt-pkg)
  assert_uses_selected_libgcrypt "libapt-pkg Hashes probe" /tmp/apt-hashes-test

  /tmp/apt-hashes-test > /tmp/apt-hashes.out
  sha256sum /tmp/apt-hashes-input.txt | cut -d' ' -f1 > /tmp/apt-sha256.out
  sha1sum /tmp/apt-hashes-input.txt | cut -d' ' -f1 > /tmp/apt-sha1.out
  head -n 1 /tmp/apt-hashes.out | diff -u - /tmp/apt-sha256.out
  sed -n '2p' /tmp/apt-hashes.out | diff -u - /tmp/apt-sha1.out
}

compile_libssh_probe() {
  local source="${REPO_DIR}/safe/tests/dependents/probes/libssh-test.c"
  local sshd_pid=''

  id -u sshuser >/dev/null 2>&1 || useradd -m -s /bin/bash sshuser
  printf 'sshuser:secretpw\n' | chpasswd

  cc -O2 -o /tmp/libssh-test "${source}" $(pkg-config --cflags --libs libssh)
  assert_uses_selected_libgcrypt "libssh-gcrypt client probe" /tmp/libssh-test

  ssh-keygen -A >/dev/null
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
  sshd_pid="$(cat /tmp/sshd_test.pid)"
  /tmp/libssh-test
  kill "${sshd_pid}" 2>/dev/null || true
}

compile_xmlsec_probe() {
  local source="${REPO_DIR}/safe/tests/dependents/probes/xmlsec-gcrypt-verify-rsa.c"
  local fixture="${REPO_DIR}/safe/tests/dependents/fixtures/xmlsec1/signature-enveloping-rsa.xml"

  cc -O2 -o /tmp/xmlsec-gcrypt-verify-rsa "${source}" \
    $(pkg-config --cflags --libs xmlsec1-gcrypt)
  assert_uses_selected_libgcrypt "xmlsec1 gcrypt backend probe" /tmp/xmlsec-gcrypt-verify-rsa

  /tmp/xmlsec-gcrypt-verify-rsa "${fixture}" |
    grep -q 'xmlsec-gcrypt-rsa-verify-ok'
}

run_compile_probes() {
  compile_apt_probe
  compile_libssh_probe
  compile_xmlsec_probe
}

run_scenarios() {
  mapfile -t scenarios < <(
    python3 - "${REPO_DIR}/safe/tests/dependents/metadata/matrix-manifest.json" <<'PY'
import json
import sys
from pathlib import Path
manifest = json.loads(Path(sys.argv[1]).read_text())
for row in manifest["rows"]:
    if row["kind"] == "executable_application":
        print(row["scenario"])
PY
  )

  for scenario in "${scenarios[@]}"; do
    echo "run-dependent-image-tests: scenario ${scenario}"
    bash "${REPO_DIR}/${scenario}"
  done
}

case "${MODE}" in
  compile-probes)
    run_compile_probes
    ;;
  all)
    run_compile_probes
    run_scenarios
    ;;
esac

echo "run-dependent-image-tests: ok (${IMPLEMENTATION}, ${MODE})"
