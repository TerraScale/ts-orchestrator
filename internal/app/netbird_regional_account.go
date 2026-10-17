package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

// Each independent reconciliation owns one finite original reader; no reconnect,
// replacement credential or restored cursor can continue its account effects.
type netBirdRegionalAccount struct {
	process    *rootoci.ProcessWitness
	intentWire []byte
	reader     *rootsecret.NetBirdReader
	control    *authority.NetBirdRead
	public     *authority.NetBirdSourceRead
	material   region.VerifiedBootstrapMaterial
	floor      region.VerifiedRegionalTrustFloor
	genesis    trust.Keyring
	cell       string
	failure    error
}

func openNetBirdRegionalAccount(ctx context.Context, local automaticFoundation, admission region.VerifiedNetBirdManager, process *rootoci.ProcessWitness, cell string) (*netBirdRegionalAccount, error) {
	if err := process.Verify(); err != nil {
		return nil, err
	}
	reader, err := rootsecret.OpenNetBirdReader(ctx, admission, cell)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*netBirdRegionalAccount, error) { reader.Conn().Close(); return nil, err }
	ctx, cancel := context.WithTimeout(reader.Context(), 10*time.Second)
	defer cancel()
	proof, err := reader.SignReadOpen(entityid.New())
	if err != nil {
		return fail(err)
	}
	wire, err := json.Marshal(proof)
	if err != nil {
		return fail(err)
	}
	reply, err := reader.Conn().RequestWithContext(ctx, netBirdReadOpenSubject(cell), wire)
	if err != nil {
		return fail(err)
	}
	var opened struct {
		Nonce string `json:"nonce"`
	}
	if protocol.DecodeStrict(reply.Data, &opened, 4096) != nil || opened.Nonce != proof.Nonce || reader.Guard(ctx) != nil {
		return fail(errors.New("NetBird regional read-open was not acknowledged by its original source"))
	}
	js, err := jetstream.New(reader.Conn())
	if err != nil {
		return fail(err)
	}
	s := &netBirdRegionalAccount{process: process, reader: reader, cell: cell}
	s.control, err = authority.ConnectNetBirdRead(ctx, js, strings.ToLower(cell), proof.Nonce)
	if err != nil {
		return fail(err)
	}
	s.public, err = authority.ConnectNetBirdSourceRead(ctx, js, proof.Nonce)
	if err != nil {
		return fail(err)
	}
	s.material, err = reader.Source().Resolver().BootstrapMaterial(ctx, cell)
	if err != nil {
		return fail(err)
	}
	s.genesis, err = bootstrapstart.LoadImageRoots()
	if err != nil {
		return fail(err)
	}
	// The recipient is admitted in HOME; the protected floor belongs to the
	// target region and is read with that region's genuine SDK authority.
	target, err := local.factory.ForRegion(s.material.Config().Region)
	if err != nil {
		return fail(err)
	}
	s.floor, err = region.OpenRegionalTrustFloor(reader.Context(), target, s.genesis, cell)
	if err != nil {
		return fail(err)
	}
	if process.Verify() != nil || reader.Guard(ctx) != nil || s.material.Revalidate(ctx) != nil {
		return fail(errors.New("NetBird regional account source changed during admission"))
	}
	return s, nil
}

func (s *netBirdRegionalAccount) end(err error) error {
	failure := errors.Join(foundation.ErrAdmissionExpired, err)
	if s != nil {
		s.failure = failure
		if s.reader != nil && s.reader.Conn() != nil {
			s.reader.Conn().Close()
		}
	}
	return failure
}

// current independently authenticates the public committed proposal. A root
// receipt supplies no authority to this dedicated manager.
func (s *netBirdRegionalAccount) current(ctx context.Context, admission region.VerifiedNetBirdManager) (rootoci.NetBirdIntent, manager.Desired, error) {
	fail := func(err error) (rootoci.NetBirdIntent, manager.Desired, error) {
		return rootoci.NetBirdIntent{}, manager.Desired{}, errors.Join(errors.New("NetBird regional account source is not current"), err)
	}
	if s != nil && s.failure != nil {
		return fail(s.failure)
	}
	if s == nil || ctx == nil {
		return fail(foundation.ErrAdmissionExpired)
	}
	deadline := s.floor.ExpiresAt()
	for _, expires := range []time.Time{s.material.ExpiresAt(), admission.ExpiresAt()} {
		if expires.Before(deadline) {
			deadline = expires
		}
	}
	if !time.Now().Before(deadline) {
		return fail(s.end(errors.New("original regional account admission expired")))
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(s.reader.Context(), cancel)
	defer stop()
	if s.process.Verify() != nil || s.reader.Guard(ctx) != nil || admission.Check(ctx) != nil || s.material.Revalidate(ctx) != nil {
		return fail(s.end(errors.New("original regional account admission changed")))
	}
	entry, lease, err := s.control.Read(ctx)
	if err != nil {
		return fail(err)
	}
	var intent rootoci.NetBirdIntent
	if protocol.DecodeStrict(entry.Payload, &intent, 1<<20) != nil {
		return fail(nil)
	}
	original, err := s.control.OriginalLease(intent.LeaseRevision)
	config := s.material.Config()
	if err != nil || !entityid.Valid(intent.OperationID) || !entityid.Valid(intent.RuntimeID) || !entityid.Valid(intent.OwnerID) || intent.Epoch == 0 || intent.Cell != s.cell || intent.InstallationID != s.material.InstallationID() ||
		intent.DeploymentID != config.DeploymentID || intent.SourceGrantSHA256 != netBirdAccountDigest(s.material.FoundationGrantWire()) ||
		intent.MaterialGeneration != s.material.Generation() || intent.SubnetCIDR != config.SubnetCIDR ||
		intent.ManagerStoreGeneration != admission.StoreGeneration() || intent.ManagerStoreGeneration != entityid.Derive("netbird-foundation-store", intent.InstallationID)+":1" ||
		entry.OperationID != intent.OperationID || entry.Epoch != intent.Epoch || entry.Sequence <= original.Revision ||
		!slices.ContainsFunc(config.Slots, func(slot bootstrapmaterial.Slot) bool { return slot.Name == intent.SourceSlot }) ||
		!strings.HasPrefix(intent.SourceInstanceID, "ocid1.instance.") || len(intent.SourceInstanceID) > 512 ||
		intent.IntentRevision != 0 || !intent.IssuedAt.IsZero() || !entry.CreatedAt.Before(intent.ExpiresAt) ||
		original.DeploymentID != config.DeploymentID || original.Scope != strings.ToLower(s.cell) || original.CandidateID != intent.RuntimeID ||
		original.OwnerID != intent.OwnerID || original.Epoch != intent.Epoch || intent.ExpiresAt.After(original.ExpiresAt) ||
		lease.DeploymentID != original.DeploymentID || lease.CandidateID != original.CandidateID || lease.OwnerID != original.OwnerID ||
		lease.Epoch != original.Epoch || lease.Revision < original.Revision || !time.Now().Before(intent.ExpiresAt) || intent.ExpiresAt.After(s.material.ExpiresAt()) {
		return fail(err)
	}
	spec, root, err := s.public.Read(ctx)
	if err != nil || spec.Revision != intent.SpecRevision || root.Revision != intent.RootRevision ||
		!spec.Created.Equal(intent.SpecStreamCreated) || !root.Created.Equal(intent.RootStreamCreated) ||
		!bytes.Equal(spec.Wire, intent.SignedSpec) || !bytes.Equal(root.Wire, intent.RootChain) || netBirdAccountDigest(spec.Wire) != intent.SpecSHA256 {
		return fail(err)
	}
	if err := s.floor.CheckAdoptedSources(ctx, root.Created, root.Revision, root.Wire, spec.Created, spec.Revision, spec.Wire); err != nil {
		return fail(s.end(err))
	}
	protected := s.floor.Info()
	if protected.Cell != s.cell || protected.Broker.DeploymentID != config.DeploymentID || protected.Broker.SignedClusterID != config.ClusterID || protected.Broker.Environment != config.Environment {
		return fail(nil)
	}
	chain, err := trust.DecodeRootChain(root.Wire)
	if err != nil {
		return fail(err)
	}
	roots, err := trust.VerifyRootChain(s.genesis, trust.ChainIdentity{DeploymentID: config.DeploymentID, Cell: config.Cell, Environment: config.Environment}, chain)
	if err != nil {
		return fail(err)
	}
	if roots.Sequence != protected.Floor.RootSequence || roots.Head != protected.Floor.RootHead {
		return fail(nil)
	}
	adopted, err := cellspec.VerifyHistorical(spec.Wire, roots.Historical, cellspec.Identity{DeploymentID: config.DeploymentID, Cell: config.Cell, Environment: config.Environment})
	if err != nil || !adopted.RootSigned || adopted.Generation != intent.SpecGeneration || adopted.Generation != protected.Floor.SpecGeneration {
		return fail(err)
	}
	desired, err := netBirdAccountDesired(intent, adopted)
	if err != nil || ctx.Err() != nil || !time.Now().Before(intent.ExpiresAt) {
		return fail(err)
	}
	if s.process.Verify() != nil || s.reader.Guard(ctx) != nil || admission.Check(ctx) != nil || s.material.Revalidate(ctx) != nil ||
		s.floor.CheckAdoptedSources(ctx, root.Created, root.Revision, root.Wire, spec.Created, spec.Revision, spec.Wire) != nil {
		return fail(s.end(errors.New("original regional account admission changed before effects")))
	}
	finalSpec, finalRoots, err := s.public.Read(ctx)
	if err != nil || !reflect.DeepEqual(finalSpec, spec) || !reflect.DeepEqual(finalRoots, root) {
		return fail(err)
	}
	finalEntry, finalLease, err := s.control.Read(ctx)
	if err != nil || !reflect.DeepEqual(finalEntry, entry) || finalLease.DeploymentID != original.DeploymentID || finalLease.CandidateID != original.CandidateID ||
		finalLease.OwnerID != original.OwnerID || finalLease.Epoch != original.Epoch || finalLease.Revision < original.Revision ||
		s.reader.Context().Err() != nil || !s.reader.Conn().IsConnected() || ctx.Err() != nil || !time.Now().Before(intent.ExpiresAt) {
		return fail(err)
	}
	if s.intentWire == nil {
		s.intentWire = bytes.Clone(entry.Payload)
	} else if !bytes.Equal(s.intentWire, entry.Payload) {
		return fail(errors.New("NetBird original operation proposal changed"))
	}
	return intent, desired, nil
}

func netBirdAccountDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func netBirdAccountDesired(intent rootoci.NetBirdIntent, adopted cellspec.Verified) (manager.Desired, error) {
	hosts := make([]rootoci.NetBirdIntentHost, 0, len(adopted.HostGrants))
	var slots []manager.Slot
	for _, grant := range adopted.HostGrants {
		role := ""
		if grant.Controller != "" || slices.Contains(grant.Roles, "controller") || slices.Contains(grant.Roles, "nats") {
			role = "controller"
		} else if slices.Contains(grant.Roles, "member") || slices.Contains(grant.Roles, "terrabase") {
			role = "member"
		}
		if role != "" {
			hosts = append(hosts, rootoci.NetBirdIntentHost{Name: grant.Node, PrivateIP: grant.PrivateIP, Role: role})
			slots = append(slots, manager.Slot{Name: grant.Node, IP: grant.PrivateIP, Role: role})
		}
	}
	slices.SortFunc(hosts, func(a, b rootoci.NetBirdIntentHost) int { return strings.Compare(a.Name, b.Name) })
	if !reflect.DeepEqual(hosts, intent.Hosts) {
		return manager.Desired{}, errors.New("NetBird intent hosts differ from the exact signed inventory")
	}
	return manager.Regional(intent.Cell, intent.SubnetCIDR, slots)
}
