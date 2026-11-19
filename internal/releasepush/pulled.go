package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/nats-io/nats.go"
)

const (
	PullStatus   = "status"
	PullInstall  = "install"
	PullFetch    = "fetch"
	PullRollback = "rollback"
	PullAdopt    = "adopt"

	StateNewer   = "newer"
	StateAdopted = "adopted"

	ProvenanceBooted    = "booted"
	ProvenanceInstalled = "installed"

	stateRestoring = "restoring"
	bundleLimit    = 4 << 20
)

type PullRequest struct {
	Op      string                `json:"op"`
	Service string                `json:"service,omitempty"`
	Release releaseattest.Release `json:"release,omitzero"`
	Reason  string                `json:"reason,omitempty"`
}

func PullSubject(region, host string) string {
	return protocol.MeshPullPrefix + region + "." + host
}

func (h *Handler) ServePulled(conn *nats.Conn, region, host string) error {
	return h.serve(conn, map[string]func(context.Context, []byte) Reply{PullSubject(region, host): func(ctx context.Context, data []byte) Reply {
		reply := h.pulled(ctx, data)
		reply.Host = host
		return reply
	}})
}

func (h *Handler) pulled(ctx context.Context, data []byte) Reply {
	var request PullRequest
	if err := protocol.DecodeStrict(data, &request, 64<<10); err != nil {
		return rejected(err)
	}
	switch request.Op {
	case PullStatus:
		reply := h.version()
		payload, _ := json.Marshal(HealthRequest{Service: request.Service})
		health := h.health(ctx, payload)
		reply.Health, reply.Node, reply.Mesh = health.Health, health.Node, health.Mesh
		reply.Peer = h.Peer != nil && h.Peer()
		reply.Provenance = h.provenance()
		if installed, err := readSeq(h.SeqFile); err != nil {
			reply.Error = "installed seq unreadable: " + err.Error()
		} else {
			reply.Seq = installed.Seq
		}
		return reply
	case PullInstall:
		return h.installPulled(ctx, request.Release)
	case PullFetch:
		return h.fetchPulled(ctx, request.Release)
	case PullRollback:
		return h.rollbackPulled(ctx, request.Release, request.Reason)
	case PullAdopt:
		return h.adoptPulled(ctx, request.Release)
	}
	return rejected(fmt.Errorf("unknown pull operation %q", request.Op))
}

func (h *Handler) installPulled(ctx context.Context, release releaseattest.Release) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	claims := Claims{SHA: release.SHA, RunID: release.RunID}
	binary, err := h.verifyPulled(ctx, release)
	if err == nil && release.Channel != nil {
		err = h.recordSeq(release, binary)
	}
	if errors.Is(err, releaseattest.ErrOlder) {
		return Reply{State: StateNewer, Version: h.Revision}
	}
	if err != nil {
		if errors.Is(err, releaseattest.ErrRefused) {
			slog.WarnContext(ctx, "pulled release refused", "release", release.Tag(), "seq", release.Seq, "reason", err.Error())
			return integrityReply(release.SHA, claims, err)
		}
		return refusalReply(RefusalHost, release.SHA, binary.SHA256, claims, err)
	}
	return h.installRelease(ctx, release.SHA, binary, claims)
}

func (h *Handler) fetchPulled(ctx context.Context, release releaseattest.Release) Reply {
	binary, err := h.verifyPulled(ctx, release)
	if errors.Is(err, releaseattest.ErrOlder) {
		return Reply{State: StateNewer, Version: h.Revision}
	}
	if err == nil {
		err = h.fetch(ctx, binary)
	}
	if err != nil {
		return Reply{State: "rejected", Version: h.Revision, Error: "release not fetched: " + err.Error()}
	}
	slog.InfoContext(ctx, "release fetched in advance", "release", release.Tag(), "sha256", binary.SHA256)
	return Reply{State: "fetched", Version: h.Revision}
}

func (h *Handler) verifyPulled(ctx context.Context, release releaseattest.Release) (Binary, error) {
	if err := release.Validate(); err != nil {
		return Binary{}, err
	}
	artifact, ok := release.Binaries[runtime.GOARCH]
	if !ok {
		return Binary{}, fmt.Errorf("%w: no binary for %s", releaseattest.ErrRefused, runtime.GOARCH)
	}
	if release.Channel != nil {
		return h.verifyChannel(ctx, release, artifact)
	}
	data, err := releaseattest.Download(ctx, h.Client, release.Bundle, bundleLimit)
	var missing *releaseattest.NotFoundError
	if errors.As(err, &missing) {
		return Binary{}, fmt.Errorf("%w: no provenance attestation is published for %s", releaseattest.ErrRefused, release.Tag())
	}
	if err != nil {
		return Binary{}, err
	}
	subjects, err := h.Attest.Subjects(data, release.SHA, release.RunID)
	if err != nil {
		return Binary{}, err
	}
	digest := subjects[releaseattest.AssetPrefix+runtime.GOARCH]
	if digest == "" || digest != artifact.SHA256 {
		return Binary{}, fmt.Errorf("%w: the %s digest is not the attested one", releaseattest.ErrRefused, runtime.GOARCH)
	}
	if err := h.Source.Descends(ctx, h.Revision, release.SHA); err != nil {
		return Binary{}, err
	}
	return Binary{URL: artifact.URL, SHA256: digest}, nil
}

func (h *Handler) provenance() string {
	_, err := os.ReadFile(h.RunIDFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ProvenanceBooted
	case err != nil:
		return "unknown: install receipt unreadable: " + err.Error()
	}
	return ProvenanceInstalled
}

func (h *Handler) adoptPulled(ctx context.Context, release releaseattest.Release) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	artifact, ok := release.Binaries[runtime.GOARCH]
	installed, err := binaryIdentity(h.Binary)
	if err != nil {
		return rejected(err)
	}
	if !ok || installed != (releaseID{release.SHA, artifact.SHA256}) {
		return Reply{State: "rejected", Version: h.Revision, Error: "this host does not run the release being adopted"}
	}
	if release.Channel != nil {
		binary, err := h.verifyPulled(ctx, release)
		if err == nil {
			err = h.recordSeq(release, binary)
		}
		if err != nil {
			return rejected(err)
		}
	}
	return Reply{State: StateAdopted, Version: h.Revision, Seq: release.Seq}
}

func (h *Handler) rollbackPulled(ctx context.Context, release releaseattest.Release, reason string) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	artifact, ok := release.Binaries[runtime.GOARCH]
	installed, err := binaryIdentity(h.Binary)
	if err != nil {
		return rejected(err)
	}
	if !ok || installed != (releaseID{release.SHA, artifact.SHA256}) {
		return Reply{State: "rejected", Version: h.Revision, Error: "this host does not run the release being rolled back"}
	}
	if _, err := binaryIdentity(h.Binary + ".prev"); err != nil {
		return rejected(fmt.Errorf("no previous binary to restore: %w", err))
	}
	if h.PrepareStop != nil {
		if err := h.PrepareStop(ctx); err != nil {
			return rejected(fmt.Errorf("host refused release restart: %w", err))
		}
	}
	record := Rollback{SHA: release.SHA, SHA256: artifact.SHA256, RunID: release.RunID, Reason: reason}
	if err := writeJSON(h.RollbackFile, record); err != nil {
		if h.AbortStop != nil {
			h.AbortStop()
		}
		return rejected(err)
	}
	h.rolledBack.Store(&record)
	h.pending = installed
	return Reply{State: stateRestoring, Version: h.Revision, RolledBack: release.SHA, Error: reason}
}

func AskStatus(ctx context.Context, conn *nats.Conn, region, host string) (Reply, error) {
	body, err := json.Marshal(PullRequest{Op: PullStatus})
	if err != nil {
		return Reply{}, err
	}
	return request(ctx, conn, PullSubject(region, host), body, 2*healthHandlerBudget)
}
