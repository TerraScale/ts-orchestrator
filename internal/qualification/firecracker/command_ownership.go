package firecracker

import (
	"fmt"
	"time"
)

// quiescePendingCommands keeps each unreaped leader until its entire owned
// process group is confirmed stopped. Callers must preserve resources on error.
func quiescePendingCommands(pending *[]*Process) []string {
	retained := []*Process{}
	errs := []string{}
	for _, process := range *pending {
		if !process.Reaped {
			if e := process.Stop(5*time.Second, true); e != nil {
				retained = append(retained, process)
				errs = append(errs, fmt.Sprintf("pending qualification command %d is not confirmed stopped: %v", process.PID(), e))
			}
		}
	}
	*pending = retained
	return errs
}
