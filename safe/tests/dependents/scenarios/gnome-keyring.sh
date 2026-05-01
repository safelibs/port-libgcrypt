#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "gnome-keyring-daemon" /usr/bin/gnome-keyring-daemon

export HOME=/tmp/gnome-keyring-home
rm -rf "${HOME}"
mkdir -p "${HOME}"

dbus-run-session -- bash -lc '
  set -euo pipefail
  printf %s test-password | gnome-keyring-daemon --unlock --components=secrets >/tmp/gnome-keyring-unlock.log
  eval "$(gnome-keyring-daemon --start --components=secrets)"
  test -n "${GNOME_KEYRING_CONTROL:-}"
  test -S "${GNOME_KEYRING_CONTROL}/control"
'
