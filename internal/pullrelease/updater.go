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
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
)

const (
	DefaultPoll       = 5 * time.Minute
	DefaultHealthyFor = 15 * time.Second
	DefaultDeadline   = 3 * time.Minute
	DefaultBakeFor    = 5 * time.Minute

	checkEvery   = 2 * time.Second
	askWait      = 8 * time.Second
	installWait  = 3*time.Minute + 30*time.Second
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
	Fabric     *nats.Conn
	Hosts      func(context.Context) ([]Host, error)
	Health     func(context.Context) error
	Source     *releaseattest.Source
	Attest     releaseattest.Verifier
	Client     *http.Client
	Poll       time.Duration
	HealthyFor time.Duration
	Deadline   time.Duration
	BakeFor    time.Duration

	store    *Store
	status   Status
	revision uint64
	leading  atomic.Bool
}

func New(region, self, state string, conn, fabric *nats.Conn, handler *releasepush.Handler, hosts func(context.Context) ([]Host, error)) *Updater {
	return &Updater{Region: region, Self: self, State: state, Conn: conn, Fabric: fabric, Hosts: hosts,
		Health: func(ctx context.Context) error {
			if handler.Health == nil {
				return errors.New("this host has no health check")
			}
			return handler.Health(ctx, "").Err()
		},
		Source: handler.Source, Attest: handler.Attest, Client: handler.Client,
		Poll: DefaultPoll, HealthyFor: DefaultHealthyFor, Deadline: DefaultDeadline, BakeFor: DefaultBakeFor}
}

func (u *Updater) Run(ctx context.Context) error {
	go u.lead(ctx)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		timer.Reset(u.turn(ctx))
	}
}

func (u *Updater) lead(ctx context.Context) {
	tick := time.NewTicker(renewEvery)
	defer tick.Stop()
	for {
		if u.store == nil {
			store, err := Open(ctx, u.Fabric, u.Region)
			if err != nil {
				slog.WarnContext(ctx, "pull rollout store unavailable", "error", err)
			}
			u.store = store
		}
		if u.store != nil {
			leading, err := u.store.Lead(ctx, u.Self)
			if err != nil {
				slog.WarnContext(ctx, "pull rollout lease not renewed", "error", err)
			}
			if u.leading.Swap(leading) != leading {
				slog.InfoContext(ctx, "pull rollout ownership changed", "region", u.Region, "owner", leading)
			}
			if !leading {
				if status, _, err := u.store.Load(ctx); err == nil {
					u.mirror(ctx, status)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (u *Updater) turn(ctx context.Context) time.Duration {
	if !u.leading.Load() {
		return renewEvery
	}
	status, revision, err := u.store.Load(ctx)
	if err != nil {
		slog.WarnContext(ctx, "pull rollout record unreadable", "error", err)
		return renewEvery
	}
	u.status, u.revision = status, revision
	u.status.Region = u.Region
	if u.status.Owner != u.Self {
		slog.InfoContext(ctx, "taking over the region's pull rollout", "region", u.Region, "from", u.status.Owner, "phase", u.status.Phase)
		u.status.Owner = u.Self
		if u.status.Phase == PhaseComplete && u.status.Baked.IsZero() {
			u.status.Done = time.Now().UTC()
		}
		if !u.save(ctx) {
			return renewEvery
		}
	}
	return u.cycle(ctx)
}

func (u *Updater) cycle(ctx context.Context) time.Duration {
	if u.status.Phase == PhaseRollingBack && u.status.Target != nil {
		return u.restore(ctx)
	}
	if u.status.Phase == PhaseComplete && u.status.Target != nil && u.status.Baked.IsZero() {
		return u.bake(ctx)
	}

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
		if reason := u.predecessor(ctx, release.Tag()); reason != "" {
			u.status.Reason = reason
			u.save(ctx)
			return checkEvery
		}
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
		u.status = Status{Region: u.Region, Owner: u.Self, Phase: PhaseRolling, Target: &attested, Bad: u.status.Bad, Checked: u.status.Checked}
		if !u.save(ctx) {
			return renewEvery
		}
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
		return cmp.Or(cmp.Compare(boolRank(!u.inFlight(a.ID)), boolRank(!u.inFlight(b.ID))),
			cmp.Compare(boolRank(a.ID == u.Self), boolRank(b.ID == u.Self)), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
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
		if !u.leading.Load() {
			return renewEvery
		}
		row := u.status.host(host.ID)
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err != nil {
			return u.wait(ctx, host.Name+" does not answer: "+err.Error())
		}
		if row.State == HostNewer && row.Version == reply.Version {
			continue
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
			return u.rolledBack(ctx, row, "rolled back by its own probation: "+reply.Error)
		}
		if !onTarget && reply.Health != restartPending {
			if reason := u.regionReady(ctx, host.ID); reason != "" {
				return u.wait(ctx, reason)
			}
			row.State, row.Error = HostInstalling, ""
			if !u.save(ctx) {
				return renewEvery
			}
			reply, err = u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullInstall, Release: target}, installWait)
			if err != nil {
				return u.wait(ctx, host.Name+" install has no answer: "+err.Error())
			}
			switch {
			case reply.State == "installed" || reply.State == "current":
			case reply.State == releasepush.StateNewer:
				row.State = HostNewer
				continue
			case reply.State == "rolled_back":
				return u.rolledBack(ctx, row, "this release was already rolled back: "+reply.Error)
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
			if errors.Is(err, errChanged) {
				return renewEvery
			}
			return u.rolledBack(ctx, row, err.Error())
		}
		row.State, row.Error, row.Version, row.SHA256 = HostDone, "", target.SHA, want.SHA256
		u.save(ctx)
	}
	u.status.Phase, u.status.Reason = PhaseComplete, ""
	if u.status.Done.IsZero() {
		u.status.Done = time.Now().UTC()
	}
	if !slices.ContainsFunc(u.status.Hosts, func(row HostProgress) bool { return row.State != HostNewer }) {
		u.status.Phase, u.status.Reason = PhaseNewer, "every host already runs a release that descends from "+target.Tag()
	}
	u.save(ctx)
	if u.status.Phase == PhaseComplete {
		return u.bake(ctx)
	}
	return u.Poll
}

func (u *Updater) inFlight(id string) bool {
	row := u.status.host(id)
	return row != nil && (row.State == HostInstalling || row.State == HostGating)
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
			return fmt.Errorf("%s left the release; it runs %s %s: %s", host.Name, reply.Version, reply.SHA256, reply.Error)
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
		if !u.leading.Load() {
			return errChanged
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

func (u *Updater) rolledBack(ctx context.Context, row *HostProgress, reason string) time.Duration {
	row.State, row.Error = HostRestoring, reason
	u.status.Phase, u.status.Reason, u.status.Since = PhaseRollingBack, row.Host+": "+reason, time.Now().UTC()
	u.save(ctx)
	slog.WarnContext(ctx, "release failed on a host; restoring its previous binary", "release", u.status.Target.Tag(), "host", row.Host, "reason", reason)
	return checkEvery
}

func (u *Updater) restore(ctx context.Context) time.Duration {
	target := *u.status.Target
	var row *HostProgress
	for i := range u.status.Hosts {
		if u.status.Hosts[i].State == HostRestoring {
			row = &u.status.Hosts[i]
			break
		}
	}
	if row == nil {
		u.status.Phase = PhaseRolledBack
		u.status.markBad(target.Tag())
		u.save(ctx)
		return u.Poll
	}
	if limit := 2 * u.Deadline; time.Since(u.status.Since) > limit {
		u.status.Phase = PhaseStalled
		u.status.Reason = fmt.Sprintf("critical: %s still runs %s; its previous binary was not confirmed within %s: %s", row.Host, target.Tag(), limit, u.status.Reason)
		u.status.markBad(target.Tag())
		u.save(ctx)
		slog.ErrorContext(ctx, "release rollback stalled; the pull rollout stops holding the region", "release", target.Tag(), "host", row.Host, "reason", u.status.Reason)
		return u.Poll
	}
	running, err := releasepush.AskVersion(ctx, u.Conn, u.Region, row.ID)
	if err != nil {
		return u.restoring(ctx, row, "does not answer: "+err.Error())
	}
	row.Version, row.SHA256 = running.Version, running.SHA256
	if running.Version == target.SHA && builds(target, running.SHA256) {
		reply, err := u.ask(ctx, row.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		switch {
		case err != nil:
			return u.restoring(ctx, row, "does not answer: "+err.Error())
		case reply.Health == restartPending:
			return u.restoring(ctx, row, "restoring the previous binary")
		}
		if !u.save(ctx) {
			return renewEvery
		}
		restored, err := u.ask(ctx, row.ID, releasepush.PullRequest{Op: releasepush.PullRollback, Release: target, Reason: row.Error}, askWait)
		if err != nil || restored.State != "restoring" {
			return u.restoring(ctx, row, fmt.Sprintf("restoring the previous binary failed: %v %s", err, restored.Error))
		}
		return u.restoring(ctx, row, "restoring the previous binary")
	}
	if running.State != "" {
		return u.restoring(ctx, row, "previous binary not confirmed yet: "+running.State+" "+running.Error)
	}
	row.State = HostRolledBack
	u.status.Phase, u.status.Reason = PhaseRolledBack, row.Host+": "+row.Error
	u.status.markBad(target.Tag())
	u.save(ctx)
	slog.WarnContext(ctx, "release rolled back; the host runs its previous binary", "release", target.Tag(), "host", row.Host, "version", running.Version)
	return u.Poll
}

func (u *Updater) restoring(ctx context.Context, row *HostProgress, reason string) time.Duration {
	u.status.Reason = row.Host + ": " + reason
	u.save(ctx)
	return checkEvery
}

func builds(release releaseattest.Release, digest string) bool {
	for _, artifact := range release.Binaries {
		if artifact.SHA256 == digest {
			return true
		}
	}
	return false
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

func (u *Updater) save(ctx context.Context) bool {
	u.status.Updated = time.Now().UTC()
	revision, err := u.store.Save(ctx, u.status, u.revision)
	if err != nil {
		slog.WarnContext(ctx, "pull rollout record not saved; this manager stops until it reads it again", "error", err)
		return false
	}
	u.revision = revision
	u.mirror(ctx, u.status)
	data, err := json.Marshal(u.status)
	if err == nil {
		err = u.Conn.Publish(protocol.MeshPullProgressPrefix+u.Region, data)
	}
	if err != nil {
		slog.WarnContext(ctx, "pull rollout progress not published", "error", err)
	}
	return true
}

func (u *Updater) mirror(ctx context.Context, status Status) {
	if err := write(u.State, status); err != nil {
		slog.WarnContext(ctx, "pull rollout record not mirrored for the host's health report", "error", err)
	}
}

func (u *Updater) predecessor(ctx context.Context, tag string) string {
	order := []string{"sjc", "fra", "gru"}
	for _, region := range catalog.Founded() {
		if region.Name() == "staging" {
			order = append([]string{"staging"}, order...)
		}
	}
	index := slices.Index(order, u.Region)
	if index < 0 {
		return "region has no reviewed binary rollout position"
	}
	if index == 0 {
		return ""
	}
	previous := order[index-1]
	status, _, err := (&Store{kv: u.store.kv, region: previous}).Load(ctx)
	if err != nil {
		return previous + ": predecessor rollout unreadable: " + err.Error()
	}
	if status.Target == nil || status.Target.Tag() != tag || status.Phase != PhaseComplete || status.Done.IsZero() || status.Baked.IsZero() {
		return previous + ": waiting for the same release to complete"
	}
	if status.Baked.Sub(status.Done) < u.BakeFor {
		return previous + ": completed release is still baking"
	}
	return ""
}

func (u *Updater) bake(ctx context.Context) time.Duration {
	for i := range u.status.Hosts {
		row := &u.status.Hosts[i]
		if row.State == HostNewer {
			continue
		}
		reply, err := u.ask(ctx, row.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err != nil || reply.State != "" || reply.Health != "ok" || reply.Version != row.Version || reply.SHA256 != row.SHA256 {
			return u.rolledBack(ctx, row, fmt.Sprintf("regional bake failed: %v %s %s %s", err, reply.State, reply.Health, reply.Error))
		}
	}
	if err := u.Health(ctx); err != nil {
		return u.rolledBack(ctx, &u.status.Hosts[0], "regional bake failed: "+err.Error())
	}
	if time.Since(u.status.Done) < u.BakeFor {
		return checkEvery
	}
	if u.status.Baked.IsZero() {
		u.status.Baked = time.Now().UTC()
		u.save(ctx)
	}
	return u.Poll
}
