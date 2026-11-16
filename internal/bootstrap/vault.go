package bootstrap

import (
	"context"
	"errors"
	"time"
)

const MaxSecretBytes int64 = 1 << 20

var (
	ErrVaultSecretMismatch = errors.New("Vault secret does not match its signed reference")
	ErrMaterialization     = errors.New("bootstrap secret materialization failed")
)

// SecretBundle is the exact, base64-encoded response data for one immutable
// Vault secret version. It is separate from the OCI SDK type for offline tests.
type SecretBundle struct {
	SecretOCID    string
	VersionNumber int64
	ContentType   string
	ContentBase64 string
}

// SecretBundleReader fetches one explicitly named secret version. It must not
// resolve mutable stages such as CURRENT or LATEST.
type SecretBundleReader interface {
	GetSecretBundle(context.Context, string, int64) (SecretBundle, error)
}

// Vault retrieves and safely materializes references authorized by both a
// currently verified manifest and its current exact-instance receipt.
type Vault struct {
	reader SecretBundleReader
	now    func() time.Time
}
