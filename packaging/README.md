# Packaging

Two zero-friction install paths in addition to `go install` (see the top-level
`README.md`). Both drop `raid` (CLI) and `raidd` (daemon) into your PATH.

## One-liner installer

```sh
curl -fsSL https://raw.githubusercontent.com/offense-research/raid/main/install.sh | sh
```

`install.sh` detects your OS/arch, downloads the matching release binary from
`github.com/offense-research/raid/releases`, verifies it against the release's
`SHA256SUMS`, installs it to `~/.local/bin`, and creates the `raidd` symlink.
If no prebuilt binary exists for your platform it falls back to a source build
with `go install`.

Overrides:

| variable | meaning | default |
|---|---|---|
| `RAID_VERSION` | release tag to install | latest release |
| `RAID_PREFIX` | install prefix | `$HOME/.local` |
| `RAID_BINDIR` | directory for the binaries | `$RAID_PREFIX/bin` |
| `RAID_FROM_SOURCE` | set `1` to build with `go install` instead of downloading | unset |

```sh
# pin a version, install system-wide
curl -fsSL https://raw.githubusercontent.com/offense-research/raid/main/install.sh \
  | RAID_VERSION=v0.1.0 RAID_PREFIX=/usr/local sh
```

## Homebrew

The formula lives at `packaging/homebrew/raid.rb` and builds from the tagged
source tarball (the store uses a cgo SQLite driver, so it builds natively with
the toolchain Homebrew provides).

Install straight from this repository:

```sh
brew install --formula ./packaging/homebrew/raid.rb
```

Or tap it so `brew install raid` resolves by name:

```sh
brew tap offense-research/raid https://github.com/offense-research/raid
brew install raid
```

(`brew tap <user>/<repo>` expects the repository to be named `homebrew-<repo>`;
the explicit URL form above works for any repo name.)

Both paths install `raid`, the `raidd` symlink, and the example policies, docs,
and API schemas under the formula's `pkgshare`.

## Verifying

```sh
raid version
raidd --help
```
