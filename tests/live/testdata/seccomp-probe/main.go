package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	_, _, errno := syscall.RawSyscall(syscall.SYS_GETPPID, 0, 0, 0)
	if errno == syscall.ENOSYS {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "getppid returned errno %d, want ENOSYS\n", errno)
	os.Exit(1)
}
