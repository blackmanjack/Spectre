//go:build windows

package utils

import "golang.org/x/sys/windows"

func rawSockAvailable() bool {
	// On Windows, raw sockets require Administrator + specific registry settings.
	// Try to open a raw socket; if it fails, fall back to connect scan.
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_TCP)
	if err != nil {
		return false
	}
	windows.Closesocket(fd)
	return true
}
