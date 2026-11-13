package membership

// OCI instance lifecycle states the reconciler distinguishes. Every other
// state, including STOPPED, means the instance may still return.
const (
	LifecycleRunning     = "RUNNING"
	LifecycleTerminating = "TERMINATING"
	LifecycleTerminated  = "TERMINATED"
)

// LedgerSlot is the historically verified current HEAD of one slot.
type LedgerSlot struct {
	Attempt      uint64
	InstanceOCID string
	Complete     bool
	// Retirement is the digest of the retirement that admitted the current
	// attempt; it is empty for attempt one.
	Retirement string
}

const ()
