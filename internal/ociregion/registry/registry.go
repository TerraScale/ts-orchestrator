// Package registry reconciles the platform's private OCI container repositories.
// Repository metadata uses instance principals; pull credentials remain Vault references.
package registry

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
)

var (
	ErrOwnership = errors.New("OCIR repository ownership is not proven")
	ErrPins      = errors.New("OCIR retention inventory is missing, stale, or incomplete")
	ErrRetiring  = errors.New("OCIR image retirement already started")
)

// Repository identifies one platform repository and the admitted creating principal.
// PrincipalID is persisted before creation; later leaders retain that original
// creator from the journal even when their own admitted principal differs.
type Repository struct {
	CompartmentID string `json:"compartment_id"`
	Name          string `json:"name"`
	PrincipalID   string `json:"principal_id"`
	Owner         string `json:"owner"`
}

// Controller consumes a persistent regional KV bucket and the shared SDK client.
// Guard checks the current authority before every OCI and journal write.
type Controller struct {
	client  artifacts.ArtifactsClient
	journal jetstream.KeyValue
	guard   func(context.Context) error
	region  string
}
