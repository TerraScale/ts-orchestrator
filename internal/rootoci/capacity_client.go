package rootoci

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	OperationAdvancePoolChild    Operation = "advance_pool_child"
	OperationRetirePoolChild     Operation = "retire_pool_child"
	OperationQuarantinePoolChild Operation = "quarantine_pool_child"
	OperationObservePoolChild    Operation = "observe_pool_child"
)

var ErrPoolChildUnverified = errors.New("pool child lacks current authenticated root creation authority")

func (client *Client) AdvancePoolChild(ctx context.Context, request PoolChildExpectation) (PoolChildView, error) {
	var response PoolChildView
	err := client.invoke(ctx, OperationAdvancePoolChild, request, &response)
	return response, err
}

func (client *Client) RetirePoolChild(ctx context.Context, request PoolRetirementExpectation) (PoolRetirementView, error) {
	var response PoolRetirementView
	err := client.invoke(ctx, OperationRetirePoolChild, request, &response)
	return response, err
}

func (client *Client) QuarantinePoolChild(ctx context.Context, request PoolQuarantineExpectation) (PoolQuarantineView, error) {
	var response PoolQuarantineView
	err := client.invoke(ctx, OperationQuarantinePoolChild, request, &response)
	return response, err
}

func (client *Client) ObservePoolChild(ctx context.Context, request PoolChildObservation) (PoolChildView, error) {
	var response PoolChildView
	err := client.invoke(ctx, OperationObservePoolChild, request, &response)
	return response, err
}

// VerifiedPoolChild retains the exact root transport and original finite
// authority. Descriptive views and regional caches cannot construct this type.
type VerifiedPoolChild struct {
	view             PoolChildView
	client           *Client
	transportBinding string
}

// VerifyPoolChild mints only after the concrete client authenticated the root
// response. Direct root callers use this same guarded typed operation.
func (client *Client) VerifyPoolChild(ctx context.Context, request PoolChildObservation) (VerifiedPoolChild, error) {
	view, err := client.ObservePoolChild(ctx, request)
	if err != nil {
		return VerifiedPoolChild{}, err
	}
	if !validPoolChildAdmission(view, time.Now()) || !poolChildMatches(view, request) {
		return VerifiedPoolChild{}, ErrPoolChildUnverified
	}
	binding := client.transportBinding()
	if binding == "" {
		return VerifiedPoolChild{}, ErrPoolChildUnverified
	}
	view.BootVolumeIDs = slices.Clone(view.BootVolumeIDs)
	return VerifiedPoolChild{view: view, client: client, transportBinding: binding}, nil
}

func (proof VerifiedPoolChild) IsVerified() bool {
	return proof.client != nil && proof.transportBinding != "" &&
		proof.client.transportBinding() == proof.transportBinding && validPoolChildAdmission(proof.view, time.Now())
}

func (proof VerifiedPoolChild) View() PoolChildView {
	view := proof.view
	view.BootVolumeIDs = slices.Clone(view.BootVolumeIDs)
	return view
}

// Revalidate refuses successor sessions, grants, receipts or resource IDs.
// A newer response can never extend the original proof's expiry.
func (proof VerifiedPoolChild) Revalidate(ctx context.Context) error {
	if !proof.IsVerified() {
		return ErrPoolChildUnverified
	}
	original := proof.view
	current, err := proof.client.ObservePoolChild(ctx, PoolChildObservation{
		Cell: original.Cell, InstanceID: original.InstanceID, OperationID: original.OperationID,
		RecipeSHA256: original.RecipeSHA256, PoolID: original.PoolID, ConfigurationID: original.ConfigurationID,
		GrantSHA256: original.GrantSHA256, Generation: original.Generation,
	})
	if err != nil {
		return err
	}
	if !proof.IsVerified() || !validPoolChildAdmission(current, time.Now()) || !samePoolChildAuthority(original, current) {
		return ErrPoolChildUnverified
	}
	return nil
}

func poolChildMatches(view PoolChildView, request PoolChildObservation) bool {
	return view.Cell == request.Cell && view.InstanceID == request.InstanceID &&
		(request.OperationID == "" || request.OperationID == view.OperationID) &&
		(request.RecipeSHA256 == "" || request.RecipeSHA256 == view.RecipeSHA256) &&
		(request.PoolID == "" || request.PoolID == view.PoolID) &&
		(request.ConfigurationID == "" || request.ConfigurationID == view.ConfigurationID) &&
		(request.GrantSHA256 == "" || request.GrantSHA256 == view.GrantSHA256) &&
		(request.Generation == 0 || request.Generation == view.Generation)
}

func samePoolChildAuthority(original, current PoolChildView) bool {
	if current.ExpiresAt.Before(original.ExpiresAt) || !current.OriginalDeadline.Equal(original.OriginalDeadline) {
		return false
	}
	current.ObservedAt, current.ExpiresAt = original.ObservedAt, original.ExpiresAt
	return reflect.DeepEqual(original, current)
}

func validPoolChildAdmission(view PoolChildView, now time.Time) bool {
	_, knownCell := catalog.Lookup(view.Cell)
	if view.Stage != "attached" || !knownCell ||
		!entityid.Valid(view.OperationID) || !entityid.Valid(view.ReservationID) || view.SlotID == "" || len(view.SlotID) > 256 ||
		view.Generation == 0 || view.Epoch == 0 || view.Node == "" || len(view.Node) > 128 ||
		view.Descriptor == "" || len(view.Descriptor) > 64<<10 ||
		(view.Role != "container" && view.Role != "wasm") ||
		(view.Architecture != "arm64" && view.Architecture != "amd64") ||
		view.ObservedAt.IsZero() || view.ObservedAt.After(now) || !now.Before(view.ExpiresAt) ||
		!now.Before(view.OriginalDeadline) || view.ExpiresAt.After(view.OriginalDeadline) ||
		!view.ExpiresAt.After(view.ObservedAt) || len(view.BootVolumeIDs) != 1 {
		return false
	}
	for _, digest := range []string{view.RecipeSHA256, view.GrantSHA256, view.ProfileSHA256, view.SourceSHA256,
		view.BirthSHA256, view.AttachSHA256, view.SessionBindingSHA256} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
			return false
		}
	}
	for _, id := range []struct{ value, prefix string }{
		{view.InstanceID, "ocid1.instance."}, {view.PoolID, "ocid1.instancepool."},
		{view.ConfigurationID, "ocid1.instanceconfiguration."}, {view.BootVolumeIDs[0], "ocid1.bootvolume."},
	} {
		if !strings.HasPrefix(id.value, id.prefix) || len(id.value) > 512 || strings.ContainsAny(id.value, " \t\r\n") {
			return false
		}
	}
	ip, err := netip.ParseAddr(view.PrivateIP)
	return err == nil && ip.Is4() && ip.IsPrivate()
}
