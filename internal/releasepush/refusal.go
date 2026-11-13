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
	Preflight  bool   `json:"preflight,omitempty"`
	RunID      string `json:"run_id"`
	RunAttempt string `json:"run_attempt"`
	Reason     string `json:"reason,omitempty"`
}

func refusalReply(kind, sha, digest string, claims Claims, err error) Reply {
	reply := rejected(err)
	reply.Refusal = &Refusal{Kind: kind, SHA: sha, SHA256: digest, RunID: claims.RunID, RunAttempt: claims.RunAttempt, Reason: scrub(err.Error())}
	return reply
}
