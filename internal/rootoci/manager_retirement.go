package rootoci

import (
	"context"
	"time"
)

const OperationRetireControllerManager Operation = "retire_controller_manager"
const MaxControllerRetirementBytes = 64 << 10

// Expectations select a protected predecessor; the signed retirement is verified at root.
type RetireControllerManagerRequest struct {
	Cell            string `json:"cell"`
	Slot            string `json:"slot"`
	PriorInstanceID string `json:"priorInstanceId"`
	NodeID          string `json:"nodeId"`
	PreviousAttempt uint64 `json:"previousAttempt"`
	NodeVersion     uint64 `json:"nodeVersion"`
	Epoch           uint64 `json:"epoch"`
	Retirement      []byte `json:"retirement,omitempty"`
}

type ControllerManagerRetirementReceipt struct {
	Cell             string    `json:"cell"`
	Slot             string    `json:"slot"`
	PriorInstanceID  string    `json:"priorInstanceId"`
	NodeID           string    `json:"nodeId"`
	RetirementSHA256 string    `json:"retirementSha256"`
	Stage            string    `json:"stage"`
	PreviousAttempt  uint64    `json:"previousAttempt"`
	DemotionVersion  uint64    `json:"demotionVersion"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

func (client *Client) RetireControllerManager(ctx context.Context, request RetireControllerManagerRequest) (ControllerManagerRetirementReceipt, error) {
	var result ControllerManagerRetirementReceipt
	err := client.invoke(ctx, OperationRetireControllerManager, request, &result)
	return result, err
}

func validControllerManagerRetirement(input RetireControllerManagerRequest) bool {
	return validSelector(input.Cell) && validSelector(input.Slot) && validSelector(input.PriorInstanceID) &&
		validSelector(input.NodeID) && input.NodeVersion > 0 && input.Epoch > 0 && len(input.Retirement) <= MaxControllerRetirementBytes
}

func validControllerManagerRetirementReceipt(receipt ControllerManagerRetirementReceipt, request RetireControllerManagerRequest, call Call) bool {
	return receipt.Cell == request.Cell && receipt.Slot == request.Slot && receipt.PriorInstanceID == request.PriorInstanceID &&
		receipt.NodeID == request.NodeID && receipt.PreviousAttempt == request.PreviousAttempt &&
		validDigest(receipt.RetirementSHA256) && (receipt.Stage == "demoted" || receipt.Stage == "removed") &&
		receipt.DemotionVersion > 0 && validResponseExpiry(receipt.ExpiresAt, call)
}
