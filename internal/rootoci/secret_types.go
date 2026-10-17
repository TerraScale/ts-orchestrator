package rootoci

import "context"

// MaxGenerationChainBytes preserves bootstrap's existing signed-chain limit.
const MaxGenerationChainBytes = 64 * (64<<10 + 16<<10)

// DeliverControllerGenerationRequest selects only signed public metadata.
// The root service derives the recipient, exact versions and private paths.
type DeliverControllerGenerationRequest struct {
	Chain []byte `json:"chain"`
}

type SecretFileReceipt struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// SecretDeliveryReceipt contains no credential bytes or OCI signing material.
type SecretDeliveryReceipt struct {
	Slot             string              `json:"slot"`
	AcceptanceSHA256 string              `json:"acceptance_sha256"`
	GenerationSHA256 string              `json:"generation_sha256"`
	Files            []SecretFileReceipt `json:"files"`
}

type Credentials interface {
	DeliverControllerGeneration(context.Context, Call, DeliverControllerGenerationRequest) (SecretDeliveryReceipt, error)
}
