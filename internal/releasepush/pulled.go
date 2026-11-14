package releasepush

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/nats-io/nats.go"
)

const (
	PullStatus   = "status"
	PullInstall  = "install"
	PullRollback = "rollback"

	stateRestoring = "restoring"
	nudgeSpacing   = 10 * time.Second
	bundleLimit    = 4 << 20
)

type Nudge struct {
	Token string `json:"token,omitempty"`
	SHA   string `json:"sha"`
	RunID string `json:"run_id"`
}

type PullRequest struct {
	Op      string                `json:"op"`
	Release releaseattest.Release `json:"release,omitzero"`
	Reason  string                `json:"reason,omitempty"`
}

func PullSubject(region, host string) string {
	return protocol.MeshPullPrefix + region + "." + host
}

func (h *Handler) ServeNudge(conn *nats.Conn) error {
	return h.serve(conn, map[string]func(context.Context, []byte) Reply{SubjectNudge: h.nudge})
}

func (h *Handler) ServePulled(conn *nats.Conn, region, host string) error {
	return h.serve(conn, map[string]func(context.Context, []byte) Reply{PullSubject(region, host): func(ctx context.Context, data []byte) Reply {
		reply := h.pulled(ctx, data)
		reply.Host = host
		return reply
	}})
}

func (h *Handler) nudge(ctx context.Context, data []byte) Reply {
	var request Nudge
	if err := protocol.DecodeStrict(data, &request, 64<<10); err != nil {
		return rejected(err)
	}
	claims, err := h.Verifier.Verify(ctx, request.Token)
	if err != nil {
		return rejected(err)
	}
	if claims.JobWorkflowRef != orchWorkflow {
		return rejected(errors.New("token is not from the ts-orchestrator release workflow"))
	}
	now := time.Now().UnixNano()
	last := h.lastNudge.Load()
	if now-last < int64(nudgeSpacing) || !h.lastNudge.CompareAndSwap(last, now) {
		return Reply{State: "throttled", Version: h.Revision}
	}
	select {
	case h.Nudges <- Nudge{SHA: claims.SHA, RunID: claims.RunID}:
	default:
	}
	return Reply{State: "nudged", Version: h.Revision}
}

func (h *Handler) pulled(ctx context.Context, data []byte) Reply {
	var request PullRequest
	if err := protocol.DecodeStrict(data, &request, 64<<10); err != nil {
		return rejected(err)
	}
	switch request.Op {
	case PullStatus:
		reply := h.version()
		reply.Health = h.health(ctx, nil).Health
		return reply
	case PullInstall:
		return h.installPulled(ctx, request.Release)
	case PullRollback:
		return h.rollbackPulled(ctx, request.Release, request.Reason)
	}
	return rejected(fmt.Errorf("unknown pull operation %q", request.Op))
}

func (h *Handler) installPulled(ctx context.Context, release releaseattest.Release) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	claims := Claims{SHA: release.SHA, RunID: release.RunID}
	binary, err := h.verifyPulled(ctx, release)
	if err != nil {
		if errors.Is(err, releaseattest.ErrRefused) {
			return integrityReply(release.SHA, claims, err)
		}
		return refusalReply(RefusalHost, release.SHA, binary.SHA256, claims, err)
	}
	return h.installRelease(ctx, release.SHA, binary, claims)
}

func (h *Handler) verifyPulled(ctx context.Context, release releaseattest.Release) (Binary, error) {
	if err := release.Validate(); err != nil {
		return Binary{}, err
	}
	artifact, ok := release.Binaries[runtime.GOARCH]
	if !ok {
		return Binary{}, fmt.Errorf("%w: no binary for %s", releaseattest.ErrRefused, runtime.GOARCH)
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
