resolve_target_root() {
  local safe_dir="$1"
  local invocation_pwd="$2"
  local target_dir="${CARGO_TARGET_DIR:-${safe_dir}/target}"

  if [[ "${target_dir}" != /* ]]; then
    target_dir="${invocation_pwd}/${target_dir}"
  fi

  printf '%s\n' "${target_dir}"
}
