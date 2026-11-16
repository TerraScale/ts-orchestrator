package functions

import (
	"time"
)

// ProcessDeployment is delivered by admitted task/Vault reconciliation. It is
// trusted placement metadata, never a user-supplied worker configuration.
type ProcessDeployment struct {
	Environment     string    `json:"environment"`
	Cell            string    `json:"cell"`
	TenantID        string    `json:"tenant_id"`
	FunctionID      string    `json:"function_id"`
	Revision        string    `json:"revision"`
	Digest          string    `json:"digest"`
	MinimumSequence uint64    `json:"minimum_sequence"`
	BrokerURL       string    `json:"broker_url"`
	ExpiresAt       time.Time `json:"expires_at"`
}
