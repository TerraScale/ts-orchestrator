package rootcapacity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func growthKind(kind string) bool {
	switch kind {
	case "configuration", "pool", "point", "launch", "attach":
		return true
	default:
		return false
	}
}

func matchGrowthRequest(request common.OCIRequest, method, path string, original *region.PoolWireRecord) error {
	if original == nil {
		return errors.New("growth observation has no original protected request")
	}
	actual, err := prepareWire(request, method, path)
	if err != nil || actual.RequestSHA256 != original.RequestSHA256 || actual.RetryToken != original.RetryToken || actual.IfMatch != original.IfMatch {
		return errors.Join(err, errors.New("growth observation differs from original protected SDK request"))
	}
	return nil
}

func (a *attempt) growthBirthEpoch() (uint64, error) {
	epoch := uint64(0)
	wires := a.growthWires()
	for _, wire := range wires {
		if wire.GrowthAuthority.BirthEpoch == 0 || epoch != 0 && epoch != wire.GrowthAuthority.BirthEpoch {
			return 0, errors.New("growth lacks one original protected birth epoch")
		}
		epoch = wire.GrowthAuthority.BirthEpoch
	}
	if child, exists := a.record.PoolChildren[a.receipt.OperationID]; exists {
		if len(wires) == 0 {
			return 0, fmt.Errorf("%w: legacy reserved child has no recoverable original growth source", ErrPending)
		}
		if child.BirthEpoch == 0 || epoch != 0 && child.BirthEpoch != epoch {
			return 0, errors.New("growth changed its original protected child epoch")
		}
		epoch = child.BirthEpoch
	}
	if epoch == 0 {
		epoch = a.original.Epoch
	}
	if epoch == 0 {
		return 0, errors.New("growth has no genuine HOME birth epoch")
	}
	return epoch, nil
}

// Reused configurations from another operation are provenance, not this
// operation's admission. Every saved phase of this operation pins its source.
func (a *attempt) growthWires() []*region.PoolWireRecord {
	var wires []*region.PoolWireRecord
	for _, kind := range []string{"configuration", "pool"} {
		if create, exists := a.record.CapacityCreates[a.receipt.OperationID+":"+kind]; exists {
			wires = append(wires, &create.Request)
		}
	}
	for _, pool := range a.record.CapacityPools {
		if point, exists := pool.ConfigurationUpdates[a.receipt.OperationID]; exists {
			wires = append(wires, &point.Request)
		}
	}
	if child, exists := a.record.PoolChildren[a.receipt.OperationID]; exists {
		if child.Launch != nil {
			wires = append(wires, child.Launch)
		}
		if child.Attach != nil {
			wires = append(wires, child.Attach)
		}
	}
	return wires
}

// A new phase may outlive a completed predecessor's transient call deadline,
// but never its original signed purchase/source cap. Saved or ambiguous phases
// keep their separate original wire deadline and binding below.
func growthSourceWindow(now time.Time, source string, caps []time.Time, wires []*region.PoolWireRecord) (time.Time, error) {
	if source == "" || len(caps) == 0 {
		return time.Time{}, errors.New("growth has no original finite authority")
	}
	var deadline time.Time
	for _, cap := range caps {
		if cap.IsZero() || !now.Before(cap) {
			return time.Time{}, fmt.Errorf("%w: original growth authority expired", ErrPending)
		}
		if deadline.IsZero() || cap.Before(deadline) {
			deadline = cap
		}
	}
	for _, wire := range wires {
		if wire == nil || wire.GrowthAuthority.SourceSHA256 != source || wire.GrowthAuthority.ExpiresAt.IsZero() || !now.Before(wire.GrowthAuthority.ExpiresAt) {
			return time.Time{}, fmt.Errorf("%w: saved growth source is expired, changed or unpinned", ErrPending)
		}
		if wire.GrowthAuthority.ExpiresAt.Before(deadline) {
			deadline = wire.GrowthAuthority.ExpiresAt
		}
	}
	return deadline, nil
}

func (a *attempt) growthSource(ctx context.Context) (string, time.Time, error) {
	if !a.worker.IsVerified() || a.receipt.GrantSHA256 != a.worker.Profile().GrantDigest() ||
		a.receipt.GrantGeneration != a.worker.Profile().Generation() || a.receipt.RecipeSHA256 != a.recipe.SHA256() || !a.receipt.RetiredAt.IsZero() {
		return "", time.Time{}, errors.New("growth lacks its original signed purchase authority")
	}
	_, callerExpires, err := a.call.AuthorityBindingSHA256(ctx)
	if err != nil || a.credentials == nil {
		return "", time.Time{}, errors.Join(err, errors.New("growth has no actual admitted original caller and credentials"))
	}
	_, credentialExpires, err := a.credentials.SourceIdentity(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	receipt, err := a.receipt.FinancialReceipt()
	if err != nil {
		return "", time.Time{}, err
	}
	worker, err := a.worker.SourceIdentitySHA256()
	if err != nil {
		return "", time.Time{}, err
	}
	epoch, err := a.growthBirthEpoch()
	if err != nil {
		return "", time.Time{}, err
	}
	wires := a.growthWires()
	originalExpires := a.worker.ExpiresAt()
	if a.receipt.LaunchExpiresAt.Before(originalExpires) {
		originalExpires = a.receipt.LaunchExpiresAt
	}
	for _, expires := range []time.Time{callerExpires, credentialExpires} {
		if expires.Before(originalExpires) {
			originalExpires = expires
		}
	}
	if len(wires) != 0 {
		originalExpires = wires[0].GrowthAuthority.ExpiresAt
		for _, wire := range wires {
			if originalExpires.IsZero() || !wire.GrowthAuthority.ExpiresAt.Equal(originalExpires) {
				return "", time.Time{}, errors.New("growth changed its original signed source deadline")
			}
		}
	}
	source, err := digestValue(struct {
		Receipt         capacityledger.Receipt
		Recipe          nodescale.Recipe
		Worker          string
		BirthEpoch      uint64
		SourceExpiresAt time.Time
	}{receipt, a.recipe, worker, epoch, originalExpires})
	if err != nil {
		return "", time.Time{}, err
	}
	_, err = growthSourceWindow(time.Now(), source, []time.Time{a.worker.ExpiresAt(), a.receipt.LaunchExpiresAt, callerExpires, credentialExpires}, wires)
	return source, originalExpires, err
}

// This digest describes the exact original wire admission. Current actual
// readers, call and HOME guards remain mandatory; equality grants no authority.
func (a *attempt) growthBinding(ctx context.Context, wire *region.PoolWireRecord) (string, error) {
	principal, _, err := a.call.AuthorityBindingSHA256(ctx)
	if err != nil || principal == "" || a.credentials == nil || wire == nil {
		return "", errors.Join(err, errors.New("growth has no independently guarded original principal"))
	}
	credentials, _, err := a.credentials.SourceIdentity(ctx)
	if err != nil {
		return "", err
	}
	return digestValue(struct {
		Source, Principal, Credentials, Request, Token, IfMatch string
		FirstAttemptAt, ExpiresAt                               time.Time
		Owner, Candidate, Deployment                            string
		Epoch                                                   uint64
	}{wire.GrowthAuthority.SourceSHA256, principal, credentials, wire.RequestSHA256, wire.RetryToken, wire.IfMatch,
		wire.FirstAttemptAt, wire.ExpiresAt, a.original.OwnerID, a.original.CandidateID, a.original.DeploymentID, a.original.Epoch})
}

func growthRetryWindow(now time.Time, binding string, currentDeadline time.Time, wire *region.PoolWireRecord) (time.Time, error) {
	if wire == nil || binding == "" || wire.GrowthAuthority.BindingSHA256 != binding || wire.ExpiresAt.IsZero() || !now.Before(wire.ExpiresAt) ||
		currentDeadline.IsZero() || !now.Before(currentDeadline) {
		return time.Time{}, fmt.Errorf("%w: original growth wire is observation-only outside its original admission", ErrPending)
	}
	if currentDeadline.Before(wire.ExpiresAt) {
		return currentDeadline, nil
	}
	return wire.ExpiresAt, nil
}

func (a *attempt) growthDeadline(ctx context.Context, kind string) (time.Time, error) {
	_, expires, err := a.growthSource(ctx)
	if err != nil {
		return time.Time{}, err
	}
	wire := a.wire(kind)
	binding, err := a.growthBinding(ctx, wire)
	if err != nil {
		return time.Time{}, err
	}
	deadline := a.deadline
	if expires.Before(deadline) {
		deadline = expires
	}
	if a.worker.ExpiresAt().Before(deadline) {
		deadline = a.worker.ExpiresAt()
	}
	return growthRetryWindow(time.Now(), binding, deadline, wire)
}

func (a *attempt) revalidateGrowth(ctx context.Context) error {
	if _, _, err := a.growthSource(ctx); err != nil {
		return err
	}
	if err := a.worker.Revalidate(a.proofContext(ctx)); err != nil {
		return err
	}
	if err := a.guard(ctx); err != nil {
		return err
	}
	_, _, err := a.growthSource(ctx)
	return err
}

// Only the exact successful SDK readback paths call this, after their final
// source guard. This transient marker grants nothing and is never serialized.
func (a *attempt) completedGrowthReadback(wire *region.PoolWireRecord) {
	if wire == nil || wire.AcceptedAt.IsZero() {
		return
	}
	if a.growthReadbacks == nil {
		a.growthReadbacks = map[string]bool{}
	}
	a.growthReadbacks[wire.RequestSHA256] = true
}

func (a *attempt) growthPredecessorsComplete() error {
	for _, previous := range a.growthWires() {
		if previous.AcceptedAt.IsZero() || !a.growthReadbacks[previous.RequestSHA256] {
			return fmt.Errorf("%w: saved growth predecessor has no exact successful terminal readback", ErrPending)
		}
	}
	return nil
}

func (a *attempt) prepareGrowthWire(ctx context.Context, request common.OCIRequest, method, path string) (*region.PoolWireRecord, error) {
	if err := a.revalidateGrowth(ctx); err != nil {
		return nil, err
	}
	if err := a.growthPredecessorsComplete(); err != nil {
		return nil, err
	}
	wire, err := prepareWire(request, method, path)
	if err != nil {
		return nil, err
	}
	wire.GrowthAuthority.SourceSHA256, wire.GrowthAuthority.ExpiresAt, err = a.growthSource(ctx)
	if err != nil {
		return nil, err
	}
	wire.GrowthAuthority.BirthEpoch, err = a.growthBirthEpoch()
	if err != nil {
		return nil, err
	}
	wire.ExpiresAt = a.deadline
	if wire.GrowthAuthority.ExpiresAt.Before(wire.ExpiresAt) {
		wire.ExpiresAt = wire.GrowthAuthority.ExpiresAt
	}
	if a.worker.ExpiresAt().Before(wire.ExpiresAt) {
		wire.ExpiresAt = a.worker.ExpiresAt()
	}
	_, credentialsExpire, err := a.credentials.SourceIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !credentialsExpire.IsZero() && credentialsExpire.Before(wire.ExpiresAt) {
		wire.ExpiresAt = credentialsExpire
	}
	if !wire.FirstAttemptAt.Before(wire.ExpiresAt) {
		return nil, errors.New("growth expired before original wire reservation")
	}
	wire.GrowthAuthority.BindingSHA256, err = a.growthBinding(ctx, wire)
	if err != nil {
		return nil, err
	}
	if err := a.revalidateGrowth(ctx); err != nil {
		return nil, err
	}
	if !time.Now().Before(wire.ExpiresAt) {
		return nil, fmt.Errorf("%w: original growth admission expired during wire reservation", ErrPending)
	}
	return wire, nil
}
