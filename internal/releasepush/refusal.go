package releasepush

const PreflightHeader = "Ts-Orch-Preflight"

const (
	RefusalHost      = "host_prerequisite"
	RefusalIntegrity = "release_integrity"
)

type integrityError struct{ error }
type hostError struct{ error }

type Refusal struct {
	Kind       string `json:"kind"`
	SHA        string `json:"sha"`
	SHA256     string `json:"sha256"`
	RunID      string `json:"run_id"`
	RunAttempt string `json:"run_attempt"`
	Reason     string `json:"reason,omitempty"`
}

func refusalReply(kind, sha, digest string, claims Claims, err error) Reply {
	reply := rejected(err)
	reply.Refusal = &Refusal{Kind: kind, SHA: sha, SHA256: digest, RunID: claims.RunID, RunAttempt: claims.RunAttempt, Reason: scrub(err.Error())}
	return reply
}

type PreflightReport struct {
	Declared bool `json:"declared"`
	Executed bool `json:"executed"`
}

func (r *PreflightReport) String() string {
	if r == nil {
		return "not reported: the host's updater runs no preflight"
	}
	return "preflight declared: " + yesNo(r.Declared) + ", executed: " + yesNo(r.Executed)
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
