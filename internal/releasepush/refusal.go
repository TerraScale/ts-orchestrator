package releasepush

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

type HostVersion struct {
	ID      string   `json:"id"`
	Host    string   `json:"host"`
	Version string   `json:"version,omitempty"`
	Refusal *Refusal `json:"refusal,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func refusalReply(kind, sha, digest string, claims Claims, err error) Reply {
	reply := rejected(err)
	reply.Refusal = &Refusal{Kind: kind, SHA: sha, SHA256: digest, RunID: claims.RunID, RunAttempt: claims.RunAttempt, Reason: scrub(err.Error())}
	return reply
}
