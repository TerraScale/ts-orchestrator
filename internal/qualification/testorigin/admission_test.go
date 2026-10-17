package testorigin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootcapacity"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type admissionEvidence struct {
	Binary          bootstrapstart.RunningBinary `json:"binary"`
	AcceptedSHA256  string                       `json:"acceptedSha256"`
	ConfigSHA256    string                       `json:"configSha256"`
	GrantSHA256     string                       `json:"grantSha256"`
	FounderInstance string                       `json:"founderInstance"`
}

func provisionFoundation(ctx context.Context, world *ociWorld, bundle region.RetainedFoundation) error {
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	// Verify the actual signed three-region contract before opening even the
	// private test operator provider or sending any SDK request.
	if err := region.VerifyFoundationProvisionBundle(ctx, genesis, bundle); err != nil {
		return err
	}
	factory, err := world.OperatorFactory()
	if err != nil {
		return err
	}
	// Original foundation/writer/policy/CAS entries come from this unchanged
	// paid-provisioning producer. Missing protocol operations fail normally.
	return region.ProvisionFoundationBundle(ctx, factory, genesis, bundle)
}

// The private realm must have genuine signed baked inputs, public discovery,
// original writer/source birth and provisioned ledger state before admission.
// This function never fills missing successful records. The first absent or
// invalid production proof returns its real failure and prevents child output.
func admitAndAdvance(ctx context.Context, controllerConfig []byte, request rootoci.PoolChildExpectation) (admissionEvidence, rootoci.PoolChildView, error) {
	var evidence admissionEvidence
	var child rootoci.PoolChildView
	if _, err := bootstrapstart.NewMarkerStore().ReadIdentity(); err == nil || !errors.Is(err, os.ErrNotExist) {
		return evidence, child, errors.New("test-origin initial admission requires an absent accepted marker")
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return evidence, child, errors.New("OCI secret-unsafe environment is present")
		}
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return evidence, child, err
	}
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return evidence, child, err
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(envelope, baked.Roots, baked.Identity.AnchorExpectation(), time.Now().UTC(), bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return evidence, child, err
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, anchor.Anchor().OCIRegion)
	if err != nil {
		return evidence, child, err
	}
	resolver, err := region.NewFoundationDiscovery(factory, anchor, baked.Roots)
	if err != nil {
		return evidence, child, err
	}
	material, err := resolver.BootstrapMaterial(ctx, string(baked.Identity.Cell))
	if err != nil {
		return evidence, child, err
	}
	template, err := bootstrap.VerifyBoundStartupTemplate(ctx, factory, material.FoundationGrantWire(), baked.Roots, anchor, time.Now().UTC())
	if err != nil {
		return evidence, child, err
	}
	founder, err := bootstrapstart.VerifySourceFounder(ctx, factory, template)
	if err != nil {
		return evidence, child, err
	}
	home, err := region.NewHomeIAMAuthority(ctx, founder, resolver)
	if err != nil {
		return evidence, child, err
	}
	source, err := region.NewSourceFounder(ctx, resolver, home)
	if err != nil {
		return evidence, child, err
	}
	// This is the actual app composition, not a Gate with replaced checkers.
	// Its credential preflight reexecutes the same measured ELF as the service
	// UID. Clock health, floor publication, remote accepted export, secret pinning
	// and marker persistence stay in the unchanged production command.
	command := exec.CommandContext(ctx, "/proc/self/exe", "bootstrap-admit-initial")
	command.Stdin = bytes.NewReader(controllerConfig)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		return evidence, child, err
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return evidence, child, err
	}
	configDigest := sha256.Sum256(controllerConfig)
	if accepted.ConfigSHA256["controller.json"] != hex.EncodeToString(configDigest[:]) ||
		accepted.InstanceOCID != founder.InstanceID() || accepted.DeploymentID != baked.Identity.DeploymentID ||
		accepted.Cell != string(baked.Identity.Cell) {
		return evidence, child, errors.New("accepted identity differs from exact test admission inputs")
	}
	binary, err := bootstrapstart.VerifyAcceptedRunningBinary(accepted.Binary)
	if err != nil {
		return evidence, child, err
	}
	reader, err := rootsecret.OpenControllerReader(ctx)
	if err != nil {
		return evidence, child, err
	}
	defer reader.Conn().Close()
	if err := errors.Join(reader.Guard(ctx), source.Guard(ctx), home.Guard(ctx, 0)); err != nil {
		return evidence, child, err
	}
	capacity, err := rootcapacity.New(ctx, factory, resolver, home)
	if err != nil {
		return evidence, child, err
	}
	// RootCall is the genuine bootstrap-domain call. It does not manufacture
	// an installed IPC caller or replace the actual reservation/birth checks.
	call, err := rootoci.RootCall(ctx)
	if err != nil {
		return evidence, child, err
	}
	child, err = capacity.AdvancePoolChild(ctx, call, request)
	if err != nil {
		return evidence, rootoci.PoolChildView{}, err
	}
	if err := errors.Join(call.Guard(ctx), reader.Guard(ctx), source.Guard(ctx), home.Guard(ctx, 0)); err != nil {
		return evidence, rootoci.PoolChildView{}, err
	}
	current, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return evidence, rootoci.PoolChildView{}, err
	}
	wire, err := protocol.EncodeJSON(accepted)
	if err != nil {
		return evidence, rootoci.PoolChildView{}, err
	}
	currentWire, err := protocol.EncodeJSON(current)
	if err != nil || !bytes.Equal(wire, currentWire) {
		return evidence, rootoci.PoolChildView{}, errors.New("accepted identity changed during capacity call")
	}
	acceptedDigest := sha256.Sum256(wire)
	evidence = admissionEvidence{Binary: binary, AcceptedSHA256: hex.EncodeToString(acceptedDigest[:]),
		ConfigSHA256: hex.EncodeToString(configDigest[:]), GrantSHA256: founder.GrantDigest(), FounderInstance: founder.InstanceID()}
	return evidence, child, nil
}
