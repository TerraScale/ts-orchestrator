package pullrelease

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
)

const (
	DefaultPoll       = 5 * time.Minute
	DefaultHealthyFor = 15 * time.Second
	DefaultDeadline   = 3 * time.Minute

	checkEvery   = 2 * time.Second
	askWait      = 8 * time.Second
	installWait  = 2*time.Minute + releasepush.WorkerReplyWait
	discoverWait = time.Minute

	restartPending = "release restart pending"
)

type Host struct {
	ID   string
	Name string
}

type Updater struct {
	Region     string
	Self       string
	State      string
	Conn       *nats.Conn
	Hosts      func(context.Context) ([]Host, error)
	Health     func(context.Context) error
	Source     *releaseattest.Source
	Attest     releaseattest.Verifier
	Client     *http.Client
	Nudges     <-chan releasepush.Nudge
	Poll       time.Duration
	HealthyFor time.Duration
	Deadline   time.Duration

	status Status
}

func New(region, self, state string, conn *nats.Conn, handler *releasepush.Handler, hosts func(context.Context) ([]Host, error)) *Updater {
	return &Updater{Region: region, Self: self, State: state, Conn: conn, Hosts: hosts,
		Health: func(ctx context.Context) error {
			if handler.Health == nil {
				return errors.New("this host has no health check")
			}
			return handler.Health(ctx, "").Err()
		},
		Source: handler.Source, Attest: handler.Attest, Client: handler.Client, Nudges: handler.Nudges,
		Poll: DefaultPoll, HealthyFor: DefaultHealthyFor, Deadline: DefaultDeadline}
}

func (u *Updater) Run(ctx context.Context) error {
	loaded, err := Read(u.State)
	if err != nil {
		slog.WarnContext(ctx, "pull rollout record unreadable; starting from the hosts' versions", "error", err)
	}
	u.status = Status{Phase: PhaseIdle}
	if loaded != nil {
		u.status = *loaded
	}
	u.status.Region = u.Region
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case nudge := <-u.Nudges:
			u.status.Nudged = releaseattest.Tag(nudge.SHA, nudge.RunID)
			slog.InfoContext(ctx, "release nudge received; checking for a new release", "release", u.status.Nudged)
		case <-timer.C:
		}
		timer.Reset(u.cycle(ctx))
	}
}

func (u *Updater) cycle(ctx context.Context) time.Duration {
	u.status.Checked = time.Now().UTC()
	discover, cancel := context.WithTimeout(ctx, discoverWait)
	release, err := u.Source.Newest(discover)
	cancel()
	var limited *releaseattest.RateLimitedError
	switch {
	case errors.As(err, &limited):
		u.status.Reason = err.Error()
		u.save(ctx)
		return max(u.Poll, time.Until(limited.Until))
	case errors.Is(err, releaseattest.ErrNoRelease):
		u.status.Reason = err.Error()
		u.save(ctx)
		return u.Poll
	case err != nil:
		u.status.Reason = "release discovery: " + err.Error()
		u.save(ctx)
		return u.Poll
	}
	if u.status.bad(release.Tag()) {
		u.save(ctx)
		return u.Poll
	}
	if u.status.Target == nil || u.status.Target.Tag() != release.Tag() {
		verify, cancel := context.WithTimeout(ctx, discoverWait)
		attested, err := u.Attest.Attested(verify, u.Client, release)
		cancel()
		var missing *releaseattest.NotFoundError
		if errors.Is(err, releaseattest.ErrRefused) || errors.As(err, &missing) {
			u.refuse(ctx, release, err.Error())
			return u.Poll
		}
		if err != nil {
			u.status.Reason = "attestation check: " + err.Error()
			u.save(ctx)
			return u.Poll
		}
		slog.InfoContext(ctx, "attested release found; rolling it out", "release", attested.Tag())
		u.status = Status{Region: u.Region, Phase: PhaseRolling, Target: &attested, Bad: u.status.Bad, Nudged: u.status.Nudged, Checked: u.status.Checked}
		u.save(ctx)
	}
	return u.roll(ctx)
}

func (u *Updater) roll(ctx context.Context) time.Duration {
	target := *u.status.Target
	hosts, err := u.Hosts(ctx)
	if err != nil || len(hosts) == 0 {
		return u.wait(ctx, fmt.Sprintf("host inventory unavailable: %v", err))
	}
	slices.SortFunc(hosts, func(a, b Host) int {
		return cmp.Or(cmp.Compare(boolRank(a.ID == u.Self), boolRank(b.ID == u.Self)), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	progress := make([]HostProgress, 0, len(hosts))
	for _, host := range hosts {
		row := HostProgress{ID: host.ID, Host: host.Name, State: HostPending}
		if known := u.status.host(host.ID); known != nil {
			row = *known
		}
		progress = append(progress, row)
	}
	u.status.Hosts = progress
	if u.status.Phase != PhaseRolledBack && u.status.Phase != PhaseRefused {
		u.status.Phase = PhaseRolling
	}
	for _, host := range hosts {
		row := u.status.host(host.ID)
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err != nil {
			return u.wait(ctx, host.Name+" does not answer: "+err.Error())
		}
		row.Version, row.SHA256 = reply.Version, reply.SHA256
		want, ok := target.Binaries[reply.Arch]
		if !ok {
			return u.wait(ctx, fmt.Sprintf("%s runs %q, which the release does not build", host.Name, reply.Arch))
		}
		onTarget := reply.Version == target.SHA && reply.SHA256 == want.SHA256
		if onTarget && row.State == HostDone {
			continue
		}
		if !onTarget && reply.Health != restartPending && row.State == HostGating {
			return u.rolledBack(ctx, row, target, "rolled back by its own probation: "+reply.Error, false)
		}
		if !onTarget && reply.Health != restartPending {
			if reason := u.regionReady(ctx, host.ID); reason != "" {
				return u.wait(ctx, reason)
			}
			row.State, row.Error = HostInstalling, ""
			u.save(ctx)
			reply, err = u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullInstall, Release: target}, installWait)
			if err != nil {
				return u.wait(ctx, host.Name+" install has no answer: "+err.Error())
			}
			switch {
			case reply.State == "installed" || reply.State == "current":
			case reply.State == "rolled_back":
				return u.rolledBack(ctx, row, target, "this release was already rolled back: "+reply.Error, false)
			case reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalIntegrity:
				row.Error = reply.Refusal.Reason
				u.refuse(ctx, target, host.Name+" refused the release: "+reply.Refusal.Reason)
				return u.Poll
			default:
				row.State = HostPending
				return u.wait(ctx, host.Name+" did not install: "+cmp.Or(refusalReason(reply), reply.Error, reply.State))
			}
		}
		row.State = HostGating
		u.save(ctx)
		if host.ID == u.Self && !onTarget {
			slog.InfoContext(ctx, "installed the release on this host; its new process finishes the rollout", "release", target.Tag())
			return u.Poll
		}
		if err := u.gate(ctx, host, target, want); err != nil {
			var left *leftError
			return u.rolledBack(ctx, row, target, err.Error(), !errors.As(err, &left))
		}
		row.State, row.Error, row.Version, row.SHA256 = HostDone, "", target.SHA, want.SHA256
		u.save(ctx)
	}
	u.status.Phase, u.status.Reason = PhaseComplete, ""
	u.save(ctx)
	return u.Poll
}

func boolRank(last bool) int {
	if last {
		return 1
	}
	return 0
}

func refusalReason(reply releasepush.Reply) string {
	if reply.Refusal == nil {
		return ""
	}
	return reply.Refusal.Reason
}

func (u *Updater) regionReady(ctx context.Context, except string) string {
	hosts, err := u.Hosts(ctx)
	if err != nil {
		return "host inventory unavailable: " + err.Error()
	}
	for _, host := range hosts {
		if host.ID == except {
			continue
		}
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		switch {
		case err != nil:
			return host.Name + " does not answer: " + err.Error()
		case reply.State != "":
			return host.Name + " is in release " + reply.State
		case reply.Health != "ok":
			return host.Name + " is not healthy: " + reply.Health
		}
	}
	if err := u.Health(ctx); err != nil {
		return "region not healthy: " + err.Error()
	}
	return ""
}

func (u *Updater) gate(ctx context.Context, host Host, target releaseattest.Release, want releaseattest.Artifact) error {
	deadline := time.Now().Add(u.Deadline)
	var healthySince time.Time
	last := "no answer"
	tick := time.NewTicker(checkEvery)
	defer tick.Stop()
	for {
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		healthy := false
		switch {
		case err != nil:
			last = "no answer: " + err.Error()
		case reply.Health == restartPending:
			last = restartPending
		case reply.Version != target.SHA || reply.SHA256 != want.SHA256:
			return &leftError{fmt.Sprintf("%s left the release; it runs %s %s: %s", host.Name, reply.Version, reply.SHA256, reply.Error)}
		case reply.State != "":
			last = "release " + reply.State
		case reply.Health != "ok":
			last = reply.Health
		default:
			if err := u.Health(ctx); err != nil {
				last = "region: " + err.Error()
			} else {
				healthy = true
			}
		}
		now := time.Now()
		if !healthy {
			healthySince = time.Time{}
		} else if healthySince.IsZero() {
			healthySince = now
		}
		if healthy && now.Sub(healthySince) >= u.HealthyFor {
			return nil
		}
		if now.After(deadline) {
			return fmt.Errorf("%s not healthy for %s within %s: %s", host.Name, u.HealthyFor, u.Deadline, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

type leftError struct{ reason string }

func (e *leftError) Error() string { return e.reason }

func (u *Updater) rolledBack(ctx context.Context, row *HostProgress, target releaseattest.Release, reason string, restore bool) time.Duration {
	row.State, row.Error = HostRolledBack, reason
	u.status.Phase, u.status.Reason = PhaseRolledBack, row.Host+": "+reason
	u.status.markBad(target.Tag())
	u.save(ctx)
	slog.WarnContext(ctx, "release rolled back", "release", target.Tag(), "host", row.Host, "reason", reason)
	if restore {
		reply, err := u.ask(ctx, row.ID, releasepush.PullRequest{Op: releasepush.PullRollback, Release: target, Reason: reason}, askWait)
		if err != nil || reply.State != "restoring" {
			row.Error = fmt.Sprintf("%s; restoring the previous binary failed: %v %s", reason, err, reply.Error)
			u.save(ctx)
		}
	}
	return u.HealthyFor
}

func (u *Updater) refuse(ctx context.Context, release releaseattest.Release, reason string) {
	slog.WarnContext(ctx, "release refused", "release", release.Tag(), "reason", reason)
	u.status.Phase, u.status.Reason = PhaseRefused, release.Tag()+": "+reason
	u.status.Target = &release
	for i := range u.status.Hosts {
		if u.status.Hosts[i].State != HostDone {
			u.status.Hosts[i].State = HostPending
		}
	}
	u.status.markBad(release.Tag())
	u.save(ctx)
}

func (u *Updater) wait(ctx context.Context, reason string) time.Duration {
	if u.status.Phase != PhaseRolledBack && u.status.Phase != PhaseRefused {
		u.status.Phase = PhaseWaiting
	}
	u.status.Reason = reason
	u.save(ctx)
	return u.HealthyFor
}

func (u *Updater) ask(ctx context.Context, host string, request releasepush.PullRequest, wait time.Duration) (releasepush.Reply, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return releasepush.Reply{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	message, err := u.Conn.RequestWithContext(ctx, releasepush.PullSubject(u.Region, host), data)
	if err != nil {
		return releasepush.Reply{}, err
	}
	var reply releasepush.Reply
	if err := protocol.DecodeTolerant(message.Data, &reply, 64<<10); err != nil {
		return releasepush.Reply{}, err
	}
	return reply, nil
}

func (u *Updater) save(ctx context.Context) {
	u.status.Updated = time.Now().UTC()
	if err := write(u.State, u.status); err != nil {
		slog.WarnContext(ctx, "pull rollout record not saved", "error", err)
	}
	data, err := json.Marshal(u.status)
	if err == nil {
		err = u.Conn.Publish(protocol.MeshPullProgressPrefix+u.Region, data)
	}
	if err != nil {
		slog.WarnContext(ctx, "pull rollout progress not published", "error", err)
	}
}
