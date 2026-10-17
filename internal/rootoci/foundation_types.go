package rootoci

import "context"

type ReconcileFoundationRequest struct {
	Cell                string `json:"cell"`
	CurrentGrantDigest  string `json:"currentGrantDigest"`
	ExpectedOperationID string `json:"expectedOperationId"`
	ExpectedEpoch       uint64 `json:"expectedEpoch"`
}

type FoundationReceipt struct {
	Cell         string                       `json:"cell"`
	GrantDigest  string                       `json:"grantDigest"`
	OperationID  string                       `json:"operationId"`
	Generation   uint64                       `json:"generation"`
	Epoch        uint64                       `json:"epoch"`
	Stage        string                       `json:"stage"`
	SeatBackends map[string]FoundationBackend `json:"seatBackends,omitempty"`
}

// FoundationBackend is a fresh observation under the original root call;
// callers must request it again before authorizing a TerraBase seat restart.
type FoundationBackend struct {
	Drained bool `json:"drained"`
	Healthy bool `json:"healthy"`
}

type SourceKind string

const (
	SourceRegional  SourceKind = "regional"
	SourceHomeLink  SourceKind = "home-link"
	SourceSpokeLink SourceKind = "spoke-link"
)

type SourceRequest struct {
	Cell          string     `json:"cell"`
	Kind          SourceKind `json:"kind"`
	RecipientCell string     `json:"recipientCell,omitempty"`
}

type SourceReceipt struct {
	Cell          string     `json:"cell"`
	Kind          SourceKind `json:"kind"`
	RecipientCell string     `json:"recipientCell,omitempty"`
	GrantDigest   string     `json:"grantDigest"`
	Generation    uint64     `json:"generation"`
	ObjectKey     string     `json:"objectKey"`
}

// FoundationInstallation exposes installation operations; request expectations never grant
// authority and no provider, signing key or caller-selected payload crosses IPC.
type FoundationInstallation interface {
	ReconcileFoundation(context.Context, Call, ReconcileFoundationRequest) (FoundationReceipt, error)
	EnsureSource(context.Context, Call, SourceRequest) (SourceReceipt, error)
}

type Foundation interface {
	FoundationInstallation
	ReconcileTaskTraffic(context.Context, Call, TaskTrafficRequest) (TaskTrafficReceipt, error)
	RetireControllerManager(context.Context, Call, RetireControllerManagerRequest) (ControllerManagerRetirementReceipt, error)
}
