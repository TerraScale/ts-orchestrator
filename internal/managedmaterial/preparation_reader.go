package managedmaterial

import (
	"crypto/ed25519"
)

// PreparationReader authenticates current R3 receipts and their exact immutable
// OCI versions with public verification material. It cannot prepare a bundle.
type PreparationReader struct {
	service       PreparationService
	controllerKey ed25519.PublicKey
}
