package controllercredential

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"golang.org/x/sys/unix"
)

var ErrDelivery = errors.New("root credential delivery is unavailable or no longer authorized")

// This sits after SDK signing, limiter waits and retry interception.
type Dispatcher struct {
	Next  common.HTTPRequestDispatcher
	Guard func() error
}

func (dispatcher Dispatcher) Do(request *http.Request) (*http.Response, error) {
	if request.Context().Err() != nil || dispatcher.Guard() != nil {
		return nil, ErrDelivery
	}
	return dispatcher.Next.Do(request)
}

func ReadInstalledChain() ([]byte, error) {
	file, err := os.OpenFile(bootstrapstart.GenerationChainCopy, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrDelivery
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&0o022 != 0 || stat.Size <= 0 || stat.Size > rootoci.MaxGenerationChainBytes {
		return nil, ErrDelivery
	}
	wire, err := io.ReadAll(io.LimitReader(file, rootoci.MaxGenerationChainBytes+1))
	if err != nil || int64(len(wire)) != stat.Size {
		return nil, ErrDelivery
	}
	return wire, nil
}

func ReadExact(ctx context.Context, client *secrets.SecretsClient, reference bootstrap.SecretReference) ([]byte, time.Time, error) {
	if reference.MaxBytes <= 0 || reference.MaxBytes > bootstrap.MaxSecretBytes {
		return nil, time.Time{}, ErrDelivery
	}
	response, err := client.GetSecretBundle(ociclient.RequestContext(ctx), secrets.GetSecretBundleRequest{SecretId: new(reference.SecretOCID), VersionNumber: new(reference.VersionNumber)})
	if err != nil {
		return nil, time.Time{}, ErrDelivery
	}
	bundle := response.SecretBundle
	now := time.Now()
	if bundle.SecretId == nil || *bundle.SecretId != reference.SecretOCID || bundle.VersionNumber == nil || *bundle.VersionNumber != reference.VersionNumber ||
		bundle.TimeOfExpiry != nil && !now.Before(bundle.TimeOfExpiry.Time) || bundle.TimeOfDeletion != nil && !now.Before(bundle.TimeOfDeletion.Time) {
		return nil, time.Time{}, ErrDelivery
	}
	var encoded *string
	switch content := bundle.SecretBundleContent.(type) {
	case secrets.Base64SecretBundleContentDetails:
		encoded = content.Content
	case *secrets.Base64SecretBundleContentDetails:
		if content != nil {
			encoded = content.Content
		}
	}
	if encoded == nil || len(*encoded) == 0 || len(*encoded) > base64.StdEncoding.EncodedLen(int(reference.MaxBytes)) {
		return nil, time.Time{}, ErrDelivery
	}
	value, err := base64.StdEncoding.Strict().DecodeString(*encoded)
	digest := sha256.Sum256(value)
	if err != nil || int64(len(value)) > reference.MaxBytes || base64.StdEncoding.EncodeToString(value) != *encoded || hex.EncodeToString(digest[:]) != reference.SHA256 {
		clear(value)
		return nil, time.Time{}, ErrDelivery
	}
	var expires time.Time
	for _, deadline := range []*common.SDKTime{bundle.TimeOfExpiry, bundle.TimeOfDeletion} {
		if deadline != nil && (expires.IsZero() || deadline.Time.Before(expires)) {
			expires = deadline.Time
		}
	}
	return value, expires, nil
}
