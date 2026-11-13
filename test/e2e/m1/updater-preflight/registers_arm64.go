package main

import "golang.org/x/sys/unix"

func syscallRegisters(tid int) (uint64, [4]uint64, int64, error) {
	var regs unix.PtraceRegsArm64
	if err := unix.PtraceGetRegSetArm64(tid, unix.NT_PRSTATUS, &regs); err != nil {
		return 0, [4]uint64{}, 0, err
	}
	return regs.Regs[8], [4]uint64{regs.Regs[0], regs.Regs[1], regs.Regs[2], regs.Regs[3]}, int64(regs.Regs[0]), nil
}
