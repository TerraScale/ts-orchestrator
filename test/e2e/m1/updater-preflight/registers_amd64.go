package main

import "golang.org/x/sys/unix"

func syscallRegisters(tid int) (uint64, [4]uint64, int64, error) {
	var regs unix.PtraceRegsAmd64
	if err := unix.PtraceGetRegsAmd64(tid, &regs); err != nil {
		return 0, [4]uint64{}, 0, err
	}
	return regs.Orig_rax, [4]uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10}, int64(regs.Rax), nil
}
