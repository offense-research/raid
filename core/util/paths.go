// Default filesystem locations, shared by the daemon and the CLI.
//
// A privileged system deployment lives under /run/offense/raid and
// /var/lib/offense/raid. An unprivileged single-user deployment (`--solo`)
// lives under the XDG state directory so no root access is required and the
// socket/db are owned by the invoking user.
package util

import (
	"os"
	"path/filepath"
)

// SystemSocketDefault is the privileged daemon socket path.
const SystemSocketDefault = "/run/offense/raid/raid.sock"

// StateDir is the user-writable state directory for a solo deployment.
// It honors RAID_STATE_DIR, then XDG_STATE_HOME, then ~/.local/state.
func StateDir() string {
	if v := os.Getenv("RAID_STATE_DIR"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "offense", "raid")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "offense", "raid")
	}
	return filepath.Join(home, ".local", "state", "offense", "raid")
}

// StateFile joins a file name onto the solo state directory.
func StateFile(name string) string { return filepath.Join(StateDir(), name) }

// DefaultSocket resolves the socket clients should talk to: an explicit
// RAID_SOCKET wins; otherwise the privileged system socket when it already
// exists; otherwise the solo state socket.
func DefaultSocket() string {
	if v := os.Getenv("RAID_SOCKET"); v != "" {
		return v
	}
	if _, err := os.Stat(SystemSocketDefault); err == nil {
		return SystemSocketDefault
	}
	return StateFile("raid.sock")
}

// DefaultDB resolves the daemon database path (RAID_DB wins).
func DefaultDB() string {
	if v := os.Getenv("RAID_DB"); v != "" {
		return v
	}
	return StateFile("raid.db")
}

// DefaultKey resolves the signing seed path (RAID_KEY wins).
func DefaultKey() string {
	if v := os.Getenv("RAID_KEY"); v != "" {
		return v
	}
	return StateFile("ed25519.seed")
}
