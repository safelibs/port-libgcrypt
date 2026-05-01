#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
implementation=original
tag=

usage() {
  cat <<'EOF'
Usage: test-original.sh [--implementation original|safe] [--tag IMAGE_TAG]
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --implementation)
      implementation="$2"
      shift 2
      ;;
    --tag)
      tag="$2"
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
  original|safe) ;;
  *)
    echo "unsupported implementation: ${implementation}" >&2
    exit 1
    ;;
esac

if [[ -z "${tag}" ]]; then
  tag="libgcrypt-dependent:${implementation}"
fi

"${repo_root}/safe/scripts/build-dependent-image.sh" \
  --implementation "${implementation}" \
  --tag "${tag}"
"${repo_root}/safe/scripts/run-dependent-image-tests.sh" \
  --implementation "${implementation}" \
  --tag "${tag}" \
  --all
