//go:build !linux

/*
 * splice_other.go - Stub for non-Linux platforms.
 *
 * The splice() syscall is Linux-specific. On other platforms (macOS, Windows, BSD),
 * these functions return false/error to trigger fallback to traditional io.Copy.
 */

package ss5

import "errors"

/* Returns false on non-Linux platforms. */
func spliceAvailable() bool {
	return false
}

/* Stub for non-Linux platforms. */
func spliceSyscall(srcFd, dstFd, maxLen int) (int, error) {
	return 0, errors.New("splice not available on this platform")
}

/* Stub for non-Linux platforms. */
func spliceToPipe(srcFd, dstFd, maxLen int) (int, error) {
	return 0, errors.New("splice not available on this platform")
}
