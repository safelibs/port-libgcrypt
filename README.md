# port-libgcrypt

SafeLibs port of `libgcrypt` for Ubuntu 24.04. Built via `dpkg-buildpackage` rooted in `safe/debian/`.

This repository follows the [`safelibs/port-template`](https://github.com/safelibs/port-template) contract. See [`AGENTS.md`](AGENTS.md) for the canonical layout, hook-script contracts, and CI sequence.

## Layout

- `original/` — pinned upstream `libgcrypt` source for differential testing.
- `safe/` — Rust workspace plus `safe/debian/` packaging metadata for the safe port.
- `test-original.sh` — port-internal differential test harness; runs the upstream regression suite against either `original` or `safe`.
- `scripts/` — template hook scripts (`install-build-deps.sh`, `build-debs.sh`, etc.).
- `packaging/package.env` — `SAFELIBS_LIBRARY` identifier for the validator hook; the `DEB_*` fields are scaffolding (the real metadata lives in `safe/debian/`).

## Local Build

```sh
bash scripts/install-build-deps.sh
bash scripts/check-layout.sh
rm -rf build dist
bash scripts/build-debs.sh
```

`.deb` artifacts land in `dist/`.
