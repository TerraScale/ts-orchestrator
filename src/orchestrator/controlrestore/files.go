package controlrestore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// FileConfig is constructed from already verified original host admission.
// Neither receipt object locations nor transition identities are user-selected.
type FileConfig struct {
	Plan                          controltransition.VerifiedPlan
	NodeID                        string
	AdmittedReceiptPrivateKeyFile string
	Identity                      ociinstance.Config
}

func PhaseReceiptKey(v controltransition.VerifiedPlan, phase string) (string, error) {
	p, err := v.Plan()
	if err != nil {
		return "", err
	}
	node := p.Source.NodeID
	switch phase {
	case "source-quiesced", "source-store-copied", "final-capture":
	case "final-restored-r3":
		node = p.Destinations[0].NodeID
	default:
		return "", errors.New("controlrestore: undeclared receipt phase")
	}
	return p.Destinations[0].Objects.Prefix + "/" + v.Digest() + "/" + phase + "/" + node + ".json", nil
}

type phaseObjects struct {
	remote    *OCIObjects
	transport *provider.OCIHTTPTransport
}

func newPhaseObjects(v controltransition.VerifiedPlan, transport *provider.OCIHTTPTransport) (*phaseObjects, error) {
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	location := p.Destinations[0].Objects
	if transport == nil || transport.Client == nil || transport.Config.Region != location.OCIRegion {
		return nil, errors.New("controlrestore: phase region differs")
	}
	reader, err := provider.NewOCIObjectStorageReader(transport, provider.ObjectReadScope{Namespace: location.Namespace, Bucket: location.Bucket, Prefix: location.Prefix + "/" + v.Digest() + "/", MaxObjectBytes: controltransition.MaximumBytes})
	if err != nil {
		return nil, err
	}
	client := *transport.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	safe, err := provider.NewOCIHTTPTransport(transport.Config, &client, transport.Signer)
	if err != nil {
		return nil, err
	}
	return &phaseObjects{remote: &OCIObjects{plan: v, location: location, reader: reader}, transport: safe}, nil
}
func (p *phaseObjects) read(ctx context.Context, phase string) ([]byte, bool, error) {
	if err := p.remote.check(ctx); err != nil {
		return nil, false, err
	}
	key, err := PhaseReceiptKey(p.remote.plan, phase)
	if err != nil {
		return nil, false, err
	}
	ref := provider.ObjectRef{Namespace: p.remote.location.Namespace, Bucket: p.remote.location.Bucket, Name: key}
	head, found, err := p.remote.reader.HeadObject(ctx, ref)
	if err != nil || !found {
		return nil, found, err
	}
	body, metadata, err := p.remote.reader.GetObject(ctx, ref)
	if err != nil {
		return nil, false, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(body, controltransition.MaximumBytes+1))
	closeErr := body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, false, err
	}
	if len(raw) == 0 || len(raw) > controltransition.MaximumBytes || head.ETag == "" || head.ETag != metadata.ETag || head.Size != int64(len(raw)) || metadata.Size != head.Size || metadata.SHA256 != head.SHA256 || controltransition.Digest(raw) != head.SHA256 {
		return nil, false, errors.New("controlrestore: phase receipt object changed")
	}
	if err := p.remote.check(ctx); err != nil {
		return nil, false, err
	}
	return raw, true, nil
}
func (p *phaseObjects) publish(ctx context.Context, phase string, raw []byte) error {
	if len(raw) == 0 || len(raw) > controltransition.MaximumBytes {
		return errors.New("controlrestore: phase receipt exceeds bound")
	}
	if err := p.remote.check(ctx); err != nil {
		return err
	}
	key, err := PhaseReceiptKey(p.remote.plan, phase)
	if err != nil {
		return err
	}
	ref := provider.ObjectRef{Namespace: p.remote.location.Namespace, Bucket: p.remote.location.Bucket, Name: key}
	response, uploadErr := p.transport.PutObjectBody(ctx, ref, bytes.NewReader(raw), map[string]string{"If-None-Match": "*", "opc-meta-terrascale-sha256": controltransition.Digest(raw)})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	got, found, err := p.read(ctx, phase)
	if err != nil {
		return errors.Join(uploadErr, err)
	}
	if !found || !bytes.Equal(got, raw) {
		return errors.New("controlrestore: immutable phase receipt conflicts")
	}
	return nil
}
func (p *phaseObjects) Read(ctx context.Context) ([]byte, bool, error) {
	return p.read(ctx, "final-restored-r3")
}
func (p *phaseObjects) Publish(ctx context.Context, raw []byte) error {
	return p.publish(ctx, "final-restored-r3", raw)
}

// ReadPhaseReceipt returns exact independently readable bytes. Callers must
// verify the matching typed signature and full predecessor chain before use.
func ReadPhaseReceipt(ctx context.Context, v controltransition.VerifiedPlan, phase string, transport *provider.OCIHTTPTransport) ([]byte, bool, error) {
	store, err := newPhaseObjects(v, transport)
	if err != nil {
		return nil, false, err
	}
	return store.read(ctx, phase)
}

// PublishSourceReceipts publishes the verified final predecessor chain using
// immutable writes; it cannot turn a preliminary capture into a final cut.
func PublishSourceReceipts(ctx context.Context, v controltransition.VerifiedPlan, cut, source, capture []byte, transport *provider.OCIHTTPTransport) error {
	if _, err := controltransition.VerifyCaptureReceipt(v, cut, source, capture); err != nil {
		return err
	}
	store, err := newPhaseObjects(v, transport)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		phase string
		raw   []byte
	}{{"source-quiesced", source}, {"source-store-copied", cut}, {"final-capture", capture}} {
		if err := store.publish(ctx, entry.phase, entry.raw); err != nil {
			return err
		}
	}
	return nil
}

// RunFiles is the actual finite guest entrypoint. The dispatcher supplies its
// admitted broker runtime and original host delivery's private receipt-key path.
func RunFiles(ctx context.Context, c FileConfig, runtime Runtime) ([]byte, error) {
	p, err := c.Plan.Plan()
	if err != nil {
		return nil, err
	}
	if c.NodeID != p.Destinations[0].NodeID || c.Identity.Region != p.Destinations[0].Objects.OCIRegion {
		return nil, errors.New("controlrestore: file configuration differs from destination")
	}
	identity, err := ociinstance.NewFromConfig(ctx, c.Identity, func(path string) ([]byte, error) { return initialgrant.ReadMaterialFile(path, 1<<20, true) })
	if err != nil {
		return nil, err
	}
	defer identity.Close()
	transport, err := identity.NewTransportForRegion(provider.OCIServiceObjectStorage, c.Identity.Region, max(p.Limits.MaxSnapshotBytes, controltransition.MaximumBytes))
	if err != nil {
		return nil, err
	}
	store, err := newPhaseObjects(c.Plan, transport)
	if err != nil {
		return nil, err
	}
	read := func(phase string) ([]byte, error) {
		raw, found, err := store.read(ctx, phase)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("controlrestore: required final predecessor absent")
		}
		return raw, nil
	}
	source, err := read("source-quiesced")
	if err != nil {
		return nil, err
	}
	cut, err := read("source-store-copied")
	if err != nil {
		return nil, err
	}
	capture, err := read("final-capture")
	if err != nil {
		return nil, err
	}
	objects, err := NewOCIObjects(c.Plan, cut, source, capture, "gru", transport)
	if err != nil {
		return nil, err
	}
	signer, err := security.LoadCommandSignatureSignerPEM(c.AdmittedReceiptPrivateKeyFile)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	return Run(ctx, Config{Plan: c.Plan, NodeID: c.NodeID, CutReceipt: cut, SourceStateReceipt: source, CaptureReceipt: capture, Objects: objects, Receipts: store, Runtime: runtime, Signer: signer})
}
