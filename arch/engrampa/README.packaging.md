# Engrampa packaging provenance

This package uses the official Arch Linux Engrampa packaging
recipe and window-sizing patch without modification.

- Packaging repository:
  https://gitlab.archlinux.org/archlinux/packaging/packages/engrampa
- Packaging revision:
  e442041cc10c4080d78473a9fcdec75872b34688
- Packaging tag: 1.28.5-3
- Packaging licensing: see LICENSE.packaging, LICENSES and REUSE.toml
- Upstream: https://github.com/mate-desktop/engrampa
- Upstream source tag: v1.28.5
- Upstream license: GPL-2.0-or-later
- Auxiliary source: https://github.com/mate-desktop/mate-submodules
- Official patch: engrampa-fix-window-size.patch

The original PKGBUILD attribution, source integrity checksums,
submodule checkout, patch, build configuration and package
version are preserved.

The official Arch patch addresses window growth when using
client-side decorations:

https://github.com/mate-desktop/engrampa/pull/559

Repository build, validation, signing and publication are
managed by the T4T3Z0R shared package pipeline.
