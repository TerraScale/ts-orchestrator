package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// The existing operator identity creates the first protected records before
// any instance principal is allowed to become their writer.
type foundationOperator struct {
	factory  *ociclient.Factory
	objects  *objectstorage.ObjectStorageClient
	genesis  trust.Keyring
	bundle   RetainedFoundation
	domain   bootstrap.StorageDomain
	id       string
	deadline time.Time
	buckets  map[string]string
	memo     *foundationVerificationMemo

	originOnce   sync.Once
	originWire   []byte
	originSchema int
	originErr    error
}

// workloadOrigin derives the immutable bundle bytes and grant schema once; the
// operator bundle never changes after construction.
func (operator *foundationOperator) workloadOrigin() ([]byte, int, error) {
	operator.originOnce.Do(func() {
		expected, err := json.Marshal(operator.bundle, json.Deterministic(true))
		if err != nil {
			operator.originErr = err
			return
		}
		envelope, err := trust.DecodeEnvelope(operator.bundle.GrantWire)
		if err != nil {
			operator.originErr = err
			return
		}
		var grant FoundationGrant
		if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
			operator.originErr = err
			return
		}
		operator.originWire, operator.originSchema = expected, grant.SchemaVersion
	})
	return operator.originWire, operator.originSchema, operator.originErr
}

func (operator *foundationOperator) guardWorkloadOrigin(ctx context.Context, reader *SignedFootprint) error {
	expected, schema, err := operator.workloadOrigin()
	if err != nil {
		return err
	}
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
			name, err := release.WorkloadGenesisObject(operator.bundle.TenancyID, cell, reader.scope.Environment, role)
			if err != nil {
				return err
			}
			// Read up to the evidence bound so a different lineage is refused as such, not as oversized.
			wire, err := readDiscoveryObject(ctx, operator.objects, operator.domain.Namespace, name, MaxWorkloadGenesisEvidenceBytes)
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
				continue
			}
			if err != nil {
				return err
			}
			if schema != 3 || !bytes.Equal(wire, expected) {
				return errors.New("permanent founding workload origin refuses a different or historical lineage")
			}
		}
	}
	return nil
}

func (operator *foundationOperator) guard(ctx context.Context) error {
	if operator == nil || ctx == nil || operator.factory == nil || operator.objects == nil {
		return errors.New("initial foundation operator is unavailable")
	}
	if err := operator.checkDeadline(ctx); err != nil {
		return err
	}
	principal, err := operator.factory.Provider().UserOCID()
	if err != nil || principal != operator.id {
		return errors.New("initial foundation operator identity changed")
	}
	tenancy, err := operator.factory.Provider().TenancyOCID()
	if err != nil || tenancy != operator.bundle.TenancyID {
		return errors.New("initial foundation operator tenancy changed")
	}
	resolver, err := verifyRetainedFoundationWith(ctx, operator.bundle, operator.genesis, operator.memo)
	if err != nil {
		return err
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return errors.New("initial foundation operator lacks its independent signed scope")
	}
	if err := operator.guardWorkloadOrigin(ctx, reader); err != nil {
		return err
	}
	// Missing discovery permits the initial provisioning sequence. An existing
	// different publication cannot be replaced by replaying an older bundle.
	for _, expected := range []struct {
		name string
		wire []byte
	}{
		{foundationRootChainObject, operator.bundle.RootChainWire},
		{strings.TrimSuffix(operator.domain.Prefix, "/") + "/" + foundationGrantObject, operator.bundle.GrantWire},
		{foundationDiscoveryObject, operator.bundle.AnchorWire},
	} {
		wire, err := readDiscoveryObject(ctx, operator.objects, operator.domain.Namespace, expected.name, int64(len(expected.wire)))
		if failure, ok := common.IsServiceError(err); ok && failure.GetHTTPStatusCode() == 404 {
			continue
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(wire, expected.wire) {
			return errors.New("initial foundation operator bundle differs from published authority")
		}
	}
	return operator.checkDeadline(ctx)
}

func (operator *foundationOperator) checkDeadline(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if operator.deadline.IsZero() || !time.Now().Before(operator.deadline) {
		return errors.New("initial foundation signed authority expired")
	}
	return nil
}
