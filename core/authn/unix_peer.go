// Unix peer credential validation (spec 11.3, 14.2).
//
// Raid validates the peer UID of every Unix-socket connection against a
// configured allowlist. This prevents unrelated local processes from
// reaching the daemon's agent and approver surfaces.
package authn

import (
	"net"
	"syscall"
)

// PeerUID returns the effective UID of the peer on a Unix connection.
// Returns -1 when the connection is not a Unix socket or credentials are
// unavailable.
func PeerUID(c net.Conn) int64 {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1
	}
	sc, err := uc.SyscallConn()
	if err != nil {
		return -1
	}
	var uid int64 = -1
	var credErr error
	_ = sc.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = int64(cred.Uid)
	})
	if credErr != nil {
		return -1
	}
	return uid
}

// UIDAllowed reports whether uid is in the allowlist.
func UIDAllowed(uid int64, allowed []int64) bool {
	for _, a := range allowed {
		if a == uid {
			return true
		}
	}
	return false
}