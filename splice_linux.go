//go:build linux

/*
 * splice_linux.go - Linux-specific splice system call wrapper.
 *
 * This file provides zero-copy data transfer using the Linux splice() syscall.
 * splice() moves data between file descriptors without copying to userspace.
 */

package ss5

import "syscall"

/*
 * Splice flags for syscall.Splice().
 * These are not exported in Go's syscall package.
 */
const (
	/* SPLICE_F_MOVE: attempt to move pages instead of copying. */
	spliceMove = 1

	/* SPLICE_F_NONBLOCK: don't block on I/O. */
	spliceNonblock = 2

	/* SPLICE_F_MORE: more data will be coming in a subsequent splice. */
	spliceMore = 4
)

/* Returns true on Linux where splice() is supported. */
func spliceAvailable() bool {
	return true
}

/* Performs splice from source fd to destination fd (TCP socket to pipe). */
func spliceSyscall(srcFd, dstFd, maxLen int) (int, error) {
	/*
	 * Do NOT use SPLICE_F_NONBLOCK here.
	 * In blocking mode, EAGAIN shouldn't occur. EINTR may occur (signal interrupt).
	 */
	n, err := syscall.Splice(srcFd, nil, dstFd, nil, maxLen, spliceMove)
	if err == syscall.EINTR {
		/* EINTR: interrupted by signal, retry by returning 0 with special handling. */
		return 0, err
	}
	if err == syscall.EAGAIN {
		/* EAGAIN: shouldn't happen in blocking mode, but handle it. */
		return 0, err
	}
	return int(n), err
}

/* Performs splice from pipe to destination socket (pipe to TCP socket). */
func spliceToPipe(srcFd, dstFd, maxLen int) (int, error) {
	n, err := syscall.Splice(srcFd, nil, dstFd, nil, maxLen, spliceMove)
	if err == syscall.EINTR {
		/* EINTR: interrupted by signal, retry. */
		return 0, err
	}
	if err == syscall.EAGAIN {
		/* EAGAIN: shouldn't happen in blocking mode, but handle it. */
		return 0, err
	}
	return int(n), err
}
