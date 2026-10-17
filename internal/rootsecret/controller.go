// Package rootsecret delivers accepted credentials without exporting an OCI
// provider, signing key, SDK client or unrestricted secret-reading operation.
package rootsecret

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/controllercredential"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"golang.org/x/sys/unix"
)

var ErrDelivery = controllercredential.ErrDelivery

// Service is installed only in the existing root OCI dispatcher.
type Service struct{}

func (Service) DeliverControllerGeneration(ctx context.Context, call rootoci.Call,
	request rootoci.DeliverControllerGenerationRequest,
) (rootoci.SecretDeliveryReceipt, error) {
	fail := func() (rootoci.SecretDeliveryReceipt, error) { return rootoci.SecretDeliveryReceipt{}, ErrDelivery }
	if os.Geteuid() != 0 || ctx == nil || len(request.Chain) == 0 || len(request.Chain) > rootoci.MaxGenerationChainBytes || call.Guard(ctx) != nil {
		return fail()
	}
	if operation := call.Operation(); operation != "" && operation != rootoci.OperationDeliverControllerGeneration {
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
	if err != nil || call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, accepted.Cell) {
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

type credentialDispatcher struct {
	next  common.HTTPRequestDispatcher
	guard func() error
}

func (dispatcher credentialDispatcher) Do(request *http.Request) (*http.Response, error) {
	return (controllercredential.Dispatcher{Next: dispatcher.next, Guard: dispatcher.guard}).Do(request)
}

func readInstalledChain() ([]byte, error) {
	return controllercredential.ReadInstalledChain()
}

func readExact(ctx context.Context, client *secrets.SecretsClient, reference bootstrap.SecretReference) ([]byte, time.Time, error) {
	return controllercredential.ReadExact(ctx, client, reference)
}
