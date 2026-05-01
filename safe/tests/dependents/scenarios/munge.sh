#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "munged" /usr/sbin/munged

munged_pid=''
cleanup() {
  if [[ -n "${munged_pid}" ]]; then
    kill "${munged_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

mkdir -p /etc/munge /run/munge /var/lib/munge /var/log/munge
chown -R munge:munge /etc/munge /run/munge /var/lib/munge /var/log/munge
rm -f /run/munge/munged.pid /run/munge/munge.socket.2
head -c 32 /dev/urandom > /etc/munge/munge.key
chmod 0400 /etc/munge/munge.key
chown munge:munge /etc/munge/munge.key

runuser -u munge -- munged \
  --pid-file /run/munge/munged.pid \
  --socket /run/munge/munge.socket.2
munged_pid="$(cat /run/munge/munged.pid)"

credential="$(munge -n)"
printf '%s\n' "${credential}" | unmunge > /tmp/unmunge.out

grep -q 'STATUS:          Success (0)' /tmp/unmunge.out
grep -q 'CIPHER:          aes128 (4)' /tmp/unmunge.out
grep -q 'MAC:             sha256 (5)' /tmp/unmunge.out
