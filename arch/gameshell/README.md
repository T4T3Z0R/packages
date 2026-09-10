# GameShell Arch package

This package follows GameShell's upstream `latest` prerelease tag and freezes
each published package to the exact commit to which that tag points.

The upstream standalone archive expects to create its temporary game tree and
save archive beside itself. Because `/usr/bin` and `/usr/share` are not
user-writable, the packaged launcher keeps a per-user copy under:

`${XDG_DATA_HOME:-$HOME/.local/share}/gameshell/`

Set `GAMESHELL_HOME` to use a different directory.

GameShell saves are self-extracting archives that contain both player progress
and the GameShell code that created the save. The launcher therefore prefers
the newest `gameshell-save*.sh` file when one exists. Package upgrades refresh
the starter archive for new games but deliberately do not rewrite an existing
saved game.

The package also installs the complete corresponding upstream source archive
for its exact source commit under `/usr/share/gameshell/source/`.

## Updates

The publishing workflow checks upstream's official mutable `latest` tag once per
day and whenever the package recipe or workflow changes on `main`. A new upstream
commit is built and validated as an unsigned candidate first. Signing and
publication still require approval through the repository's `arch-repo-publish`
GitHub environment.
