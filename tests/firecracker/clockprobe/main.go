// clockprobe reports the same Linux kernel clock predicate used by production
// broker admission. It is a test-only binary installed in Firecracker guests.
package main

import (
	"encoding/json/v2"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"golang.org/x/sys/unix"
)

type result struct {
	Healthy        bool      `json:"healthy"`
	CheckedAt      time.Time `json:"checked_at"`
	ElapsedNanos   int64     `json:"elapsed_nanos"`
	KernelState    int       `json:"kernel_state"`
	KernelStatus   int32     `json:"kernel_status"`
	KernelMaxError int64     `json:"kernel_maxerror_us"`
	ProbeMaxError  int64     `json:"probe_maxerror_us,omitzero"`
	KernelQueryOK  bool      `json:"kernel_query_ok"`
}

func main() {
	started := time.Now()
	bound, err := (brokerauth.KernelClockProbe{}).Measure()
	var state unix.Timex
	kernelState, kernelErr := unix.Adjtimex(&state)
	record := result{
		Healthy:        err == nil,
		CheckedAt:      time.Now().UTC(),
		ElapsedNanos:   time.Since(started).Nanoseconds(),
		KernelState:    kernelState,
		KernelStatus:   state.Status,
		KernelMaxError: state.Maxerror,
		KernelQueryOK:  kernelErr == nil,
	}
	if err == nil {
		record.ProbeMaxError = bound.MaxError.Microseconds()
	}
	encoded, marshalErr := json.Marshal(record)
	if marshalErr != nil {
		os.Exit(2)
	}
	if _, writeErr := os.Stdout.Write(append(encoded, '\n')); writeErr != nil {
		os.Exit(2)
	}
	if !record.Healthy {
		os.Exit(1)
	}
}
