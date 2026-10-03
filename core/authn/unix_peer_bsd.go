//go:build darwin || freebsd

package authn

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the effective UID of the peer on a Unix connection.
// Returns -1 when the connection is not a Unix socket or credentials are
// unavailable. macOS/FreeBSD: LOCAL_PEERCRED returns a struct xucred.
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
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
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
