// Unix peer credential validation (spec 11.3, 14.2).
//
// Raid validates the peer UID of every Unix-socket connection against a
// configured allowlist. This prevents unrelated local processes from
// reaching the daemon's agent and approver surfaces.
//
// PeerUID is platform-specific (core/authn/unix_peer_linux.go and
// unix_peer_bsd.go); UIDAllowed is shared.
package authn

// UIDAllowed reports whether uid is in the allowlist.
func UIDAllowed(uid int64, allowed []int64) bool {
	for _, a := range allowed {
		if a == uid {
			return true
		}
	}
	return false
}
