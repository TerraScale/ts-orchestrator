// Package rootsecret delivers accepted credentials without exporting an OCI
// provider, signing key, SDK client or unrestricted secret-reading operation.
package rootsecret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"golang.org/x/sys/unix"
)

var ErrDelivery = errors.New("root credential delivery is unavailable or no longer authorized")

// Service is installed only in the existing root OCI dispatcher.
type Service struct{}

func (Service) DeliverControllerGeneration(ctx context.Context, call rootoci.Call,
	request rootoci.DeliverControllerGenerationRequest,
) (rootoci.SecretDeliveryReceipt, error) {
	fail := func() (rootoci.SecretDeliveryReceipt, error) { return rootoci.SecretDeliveryReceipt{}, ErrDelivery }
	if os.Geteuid() != 0 || ctx == nil || len(request.Chain) == 0 || len(request.Chain) > rootoci.MaxGenerationChainBytes || call.Guard(ctx) != nil {
		return fail()
	}
	if call.Deadline().IsZero() || !time.Now().Before(call.Deadline()) {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx, leaseCancel := context.WithDeadline(ctx, call.Deadline())
	defer leaseCancel()
	request.Chain = bytes.Clone(request.Chain)
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return fail()
		}
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil || !strings.EqualFold(call.Expected().Cell, accepted.Cell) {
		return fail()
	}
	target, err := bootstrapstart.GenerationTargetFromAccepted(accepted)
	if err != nil {
		return fail()
	}
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return fail()
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(request.Chain)
	if err != nil {
		return fail()
	}
	verified, err := target.VerifyChain(chain, inputs.Roots.Current, time.Now().UTC())
	if err != nil || len(verified) == 0 {
		return fail()
	}
	newest := verified[len(verified)-1]
	ctx, generationCancel := context.WithDeadline(ctx, newest.ExpiresAt())
	defer generationCancel()
	installed, err := readInstalledChain()
	if err != nil {
		return fail()
	}
	if len(installed) != 0 {
		previous, err := bootstrap.DecodeMaterialGenerationChain(installed)
		if err != nil || !bootstrap.ExtendsMaterialGenerationChain(chain, previous) {
			return fail()
		}
	}
	// Reopen the accepted identity and signed root lineage before every read
	// and install; an already-open socket is not continuing authority.
	guard := func() error {
		if err := call.Guard(ctx); err != nil {
			return ErrDelivery
		}
		current, err := bootstrapstart.NewMarkerStore().ReadIdentity()
		if err != nil {
			return ErrDelivery
		}
		currentTarget, err := bootstrapstart.GenerationTargetFromAccepted(current)
		if err != nil || currentTarget.AcceptanceSHA256 != target.AcceptanceSHA256 {
			return ErrDelivery
		}
		roots, err := bootstrapstart.LoadTrustInputs(current)
		if err != nil {
			return ErrDelivery
		}
		if _, err := currentTarget.VerifyChain(chain, roots.Roots.Current, time.Now().UTC()); err != nil {
			return ErrDelivery
		}
		currentInstalled, err := readInstalledChain()
		if err != nil || !bytes.Equal(installed, currentInstalled) {
			return ErrDelivery
		}
		if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
			return ErrDelivery
		}
		return ctx.Err()
	}
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return fail()
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return fail()
	}
	directory, err := openSpool(uint32(uid), uint32(gid))
	if err != nil {
		return fail()
	}
	defer unix.Close(directory)
	region, err := target.Expected.Cell.OCIRegion()
	if err != nil || guard() != nil {
		return fail()
	}
	factory, err := ociclient.InstancePrincipal(region)
	if err != nil {
		return fail()
	}
	client, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return fail()
	}
	client.HTTPClient = credentialDispatcher{next: client.HTTPClient, guard: guard}
	receipt := rootoci.SecretDeliveryReceipt{Slot: target.Slot, AcceptanceSHA256: target.AcceptanceSHA256, GenerationSHA256: newest.Fingerprint()}
	var earliest time.Time
	for _, reference := range newest.Generation().Secrets {
		if reference.Slot != "" && reference.Slot != target.Slot {
			continue
		}
		if guard() != nil {
			return fail()
		}
		value, expires, err := readExact(ctx, &client, reference)
		if err != nil {
			return fail()
		}
		err = install(directory, reference.TargetFile, value, uint32(uid), uint32(gid), func() error {
			if guard() != nil {
				return ErrDelivery
			}
			if !expires.IsZero() && !time.Now().Before(expires) {
				return ErrDelivery
			}
			return nil
		})
		count := int64(len(value))
		clear(value)
		if err != nil {
			return fail()
		}
		if !expires.IsZero() && (earliest.IsZero() || expires.Before(earliest)) {
			earliest = expires
		}
		receipt.Files = append(receipt.Files, rootoci.SecretFileReceipt{Name: reference.TargetFile, SHA256: reference.SHA256, Bytes: count})
	}
	if guard() != nil || !earliest.IsZero() && !time.Now().Before(earliest) {
		return fail()
	}
	slices.SortFunc(receipt.Files, func(a, b rootoci.SecretFileReceipt) int { return strings.Compare(a.Name, b.Name) })
	return receipt, nil
}

// This sits after SDK signing, limiter waits and retry interception.
type credentialDispatcher struct {
	next  common.HTTPRequestDispatcher
	guard func() error
}

func (dispatcher credentialDispatcher) Do(request *http.Request) (*http.Response, error) {
	if request.Context().Err() != nil || dispatcher.guard() != nil {
		return nil, ErrDelivery
	}
	return dispatcher.next.Do(request)
}

func readInstalledChain() ([]byte, error) {
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

func readExact(ctx context.Context, client *secrets.SecretsClient, reference bootstrap.SecretReference) ([]byte, time.Time, error) {
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
