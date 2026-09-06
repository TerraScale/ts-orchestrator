package keyrotation

// MemberRotationRequest is the authenticated host credential protocol. Byte
// fields are base64 in JSON and must never be copied to public journals.
type MemberRotationRequest struct {
	OperationID       string `json:"operation_id"`
	NodeID            string `json:"node_id"`
	Consumer          string `json:"consumer"`
	Action            string `json:"action"`
	Generation        uint64 `json:"generation"`
	ExpiresAt         int64  `json:"expires_at"`
	CurrentKeyID      string `json:"current_key_id"`
	CurrentKey        []byte `json:"current_key"`
	PreviousKeyID     string `json:"previous_key_id"`
	PreviousKey       []byte `json:"previous_key"`
	PreviousExpiresAt int64  `json:"previous_expires_at"`
	WorkloadTLS       []byte `json:"workload_tls"`
	ControlTLS        []byte `json:"control_tls"`
	TrustBundle       []byte `json:"trust_bundle"`
}

// MemberRotationResponse reports the installed or validated generation. It
// deliberately contains neither provider error details nor credential values.
type MemberRotationResponse struct {
	OperationID string `json:"operation_id"`
	Generation  uint64 `json:"generation"`
	ValidUntil  int64  `json:"valid_until"`
	State       string `json:"state"`
}

const memberRotationPath = "/v1/credential-rotation"
const maximumMemberRotationBytes = 256 << 10
