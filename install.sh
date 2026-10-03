#!/bin/sh
# Raid installer - put `raid` (CLI) and `raidd` (daemon) on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/offense-research/raid/main/install.sh | sh
#
# `raid` and `raidd` are the same binary; `raidd` selects server mode by its
# argv[0] name, so this installs one binary plus a symlink.
#
# Environment:
#   RAID_VERSION      release tag to install        (default: latest release)
#   RAID_PREFIX       install prefix               (default: $HOME/.local)
#   RAID_BINDIR       directory for the binaries   (default: $RAID_PREFIX/bin)
#   RAID_FROM_SOURCE  set to 1 to build with `go install` instead of downloading
#
# Release assets are published per OS/arch alongside a SHA256SUMS file; this
# script verifies the checksum before installing the binary.
set -eu

REPO="offense-research/raid"
PREFIX="${RAID_PREFIX:-$HOME/.local}"
BINDIR="${RAID_BINDIR:-$PREFIX/bin}"
VERSION="${RAID_VERSION:-}"

say() { printf '%s\n' "$*" >&2; }
err() { printf 'raid-install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

detect_target() {
	os=$(uname -s)
	arch=$(uname -m)
	case "$os" in
	Linux) goos=linux ;;
	Darwin) goos=darwin ;;
	*) err "unsupported OS: $os (set RAID_FROM_SOURCE=1 to build from source)" ;;
	esac
	case "$arch" in
	x86_64 | amd64) goarch=amd64 ;;
	arm64 | aarch64) goarch=arm64 ;;
	*) err "unsupported architecture: $arch (set RAID_FROM_SOURCE=1 to build from source)" ;;
	esac
}

install_from_source() {
	need go
	say "[raid] building from source with 'go install'..."
	GOBIN="$BINDIR" go install "github.com/${REPO}@${VERSION:-latest}" ||
		err "go install failed"
}

install_from_release() {
	need curl
	need install
	detect_target
	asset="raid_${goos}_${goarch}"
	if [ -n "$VERSION" ]; then
		base="https://github.com/${REPO}/releases/download/${VERSION}"
	else
		base="https://github.com/${REPO}/releases/latest/download"
	fi
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM
	say "[raid] downloading ${asset}..."
	if ! curl -fsSL -o "$tmp/$asset" "${base}/${asset}"; then
		say "[raid] no prebuilt binary for ${goos}/${goarch}; falling back to source build"
		install_from_source
		return 0
	fi
	if curl -fsSL -o "$tmp/SHA256SUMS" "${base}/SHA256SUMS" 2>/dev/null; then
		want=$(grep " ${asset}\$" "$tmp/SHA256SUMS" 2>/dev/null | awk '{print $1}')
		if [ -n "$want" ]; then
			if command -v sha256sum >/dev/null 2>&1; then
				got=$(sha256sum "$tmp/$asset" | awk '{print $1}')
			elif command -v shasum >/dev/null 2>&1; then
				got=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
			else
				got=""
				say "[raid] no sha256sum/shasum available; skipping checksum verification"
			fi
			if [ -n "$got" ] && [ "$want" != "$got" ]; then
				err "checksum mismatch for ${asset} (expected ${want}, got ${got})"
			fi
			[ -n "$got" ] && say "[raid] checksum verified"
		fi
	fi
	mkdir -p "$BINDIR"
	install -m 0755 "$tmp/$asset" "$BINDIR/raid"
}

main() {
	mkdir -p "$BINDIR"
	if [ "${RAID_FROM_SOURCE:-0}" = "1" ]; then
		install_from_source
	else
		install_from_release
	fi
	ln -sf raid "$BINDIR/raidd"
	say "[raid] installed raid and raidd into $BINDIR"
	case ":${PATH}:" in
	*":${BINDIR}:"*) ;;
	*) say "[raid] add it to your PATH:  export PATH=\"${BINDIR}:\$PATH\"" ;;
	esac
	say "[raid] start a solo daemon with:  raidd --solo &"
}

main "$@"
