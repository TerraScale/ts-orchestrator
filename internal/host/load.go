package host

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// Host load telemetry: the agent samples its own load every LoadInterval and
// sends it as the "load" host operation over its authenticated session; the
// authority leader hands accepted reports to the configured LoadSink. Load
// is telemetry only: it never changes a session, a desired state or any
// lifecycle decision on either side.

const (
	// MinLoadInterval bounds how often an agent may publish load.
	MinLoadInterval = 5 * time.Second
	// maxLoadBackoff caps the retry spacing after failed publications, for
	// example while the controller has host telemetry disabled.
	maxLoadBackoff = 10 * time.Minute
	// terraBaseLoadTTL drops a TerraBase load block that no verified
	// member status refreshed recently.
	terraBaseLoadTTL = 2 * time.Minute
)

var errLoadDisabled = errors.New("host load telemetry is not enabled on this controller")

// LoadSink receives one authenticated host load report whose roles were
// filtered to the roles the host currently runs. Origin comes from the
// controller's registration state, never from the report.
type LoadSink func(origin hostload.Origin, report hostload.Report) error

type loadAck struct {
	Accepted bool `json:"accepted"`
}

// SetLoadSink enables the "load" host operation; nil disables it again.
func (c *Controller) SetLoadSink(sink LoadSink) {
	if sink == nil {
		c.loadSink.Store(nil)
		return
	}
	c.loadSink.Store(&sink)
}

func (c *Controller) storeLoad(ctx context.Context, req request, r Registration) (any, error) {
	sink := c.loadSink.Load()
	if sink == nil {
		return nil, errLoadDisabled
	}
	var report hostload.Report
	if err := decodeStrict(req.Payload, &report); err != nil {
		return nil, err
	}
	if err := report.Validate(); err != nil {
		return nil, err
	}
	// Only roles registered for this host with a current, non-withdrawn
	// allocation count: a host cannot report load for a service it does
	// not run.
	roles := report.Roles[:0]
	for _, role := range report.Roles {
		if !slices.Contains(r.Roles, role.Role) {
			continue
		}
		desired, _, exists, err := c.readDesired(ctx, req.Node, role.Role)
		if err != nil {
			return nil, err
		}
		if exists && !desired.Withdrawn {
			roles = append(roles, role)
		}
	}
	report.Roles = roles
	err := (*sink)(hostload.Origin{Cell: c.cell, Environment: r.Environment, Node: req.Node}, report)
	if errors.Is(err, hostload.ErrTooFrequent) {
		return loadAck{Accepted: false}, nil
	}
	if err != nil {
		return nil, err
	}
	return loadAck{Accepted: true}, nil
}

// terraBaseLoad is the latest load block a verified member status carried.
type terraBaseLoad struct {
	load memberstatus.Load
	at   time.Time
}

// noteTerraBaseLoad remembers the load block of a member status that passed
// every identity, mount and serving check and was reported.
func (a *Agent) noteTerraBaseLoad(role string, load *memberstatus.Load) {
	a.loadMu.Lock()
	defer a.loadMu.Unlock()
	if load == nil {
		delete(a.terraBaseLoads, role)
		return
	}
	if a.terraBaseLoads == nil {
		a.terraBaseLoads = make(map[string]terraBaseLoad)
	}
	a.terraBaseLoads[role] = terraBaseLoad{load: *load, at: time.Now()}
}

func (a *Agent) currentTerraBaseLoads() map[string]memberstatus.Load {
	a.loadMu.Lock()
	defer a.loadMu.Unlock()
	// A running member's block is refreshed on every poll, so one that
	// missed a few polls (withdrawn, draining, or stuck) is dropped well
	// before the absolute cap.
	ttl := min(max(3*a.cfg.PollInterval, MinLoadInterval), terraBaseLoadTTL)
	out := make(map[string]memberstatus.Load, len(a.terraBaseLoads))
	for role, entry := range a.terraBaseLoads {
		if time.Since(entry.at) > ttl {
			delete(a.terraBaseLoads, role)
			continue
		}
		out[role] = entry.load
	}
	return out
}

// cgroupRooted is implemented by runners that keep one cgroup v2 group per
// role under a common parent.
type cgroupRooted interface {
	CgroupRoot() string
}

// CgroupRoot is the role cgroup parent once Recover has run.
func (p *processRunner) CgroupRoot() string { return p.cgroups }

// publishLoad samples and publishes host load until ctx ends. Failures back
// off exponentially up to maxLoadBackoff and are logged once per change of
// outcome, so a controller without telemetry costs one request per backoff.
func (a *Agent) publishLoad(ctx context.Context) {
	filesystems := []observability.FilesystemRole{{Role: "state", Path: a.cfg.StateRoot},
		{Role: "install", Path: a.cfg.InstallRoot}}
	if a.cfg.ManagedRuntimeRoot != "" {
		filesystems = append(filesystems, observability.FilesystemRole{Role: "managed_runtime", Path: a.cfg.ManagedRuntimeRoot})
	}
	config := hostload.SamplerConfig{Roles: a.cfg.Roles, Filesystems: filesystems}
	if rooted, ok := a.runner.(cgroupRooted); ok {
		config.CgroupRoot = rooted.CgroupRoot()
	}
	sampler := hostload.NewSampler(config)
	// The first sample only sets CPU baselines.
	sampler.Sample(nil)
	wait, failing := a.cfg.LoadInterval, false
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if a.sessionLost.Load() {
			return
		}
		var ack loadAck
		err := a.request(ctx, "load", sampler.Sample(a.currentTerraBaseLoads()), &ack)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if !failing {
				slog.Info("host load telemetry not accepted; backing off", "error_class", loadErrorClass(err))
			}
			failing = true
			wait = nextLoadWait(wait, a.cfg.LoadInterval)
			continue
		}
		if failing {
			slog.Info("host load telemetry accepted")
		}
		failing, wait = false, a.cfg.LoadInterval
	}
}

// nextLoadWait doubles the wait after a failed publication, capped at
// maxLoadBackoff, but never below the configured interval: a failure must
// not make an agent with a long interval publish more often.
func nextLoadWait(wait, interval time.Duration) time.Duration {
	return max(min(wait*2, maxLoadBackoff), interval)
}

func loadErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case strings.Contains(err.Error(), errLoadDisabled.Error()):
		return "disabled"
	default:
		return "other"
	}
}
