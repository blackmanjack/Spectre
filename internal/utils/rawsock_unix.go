//go:build linux || darwin || freebsd

package utils

import "golang.org/x/sys/unix"

func rawSockAvailable() bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
