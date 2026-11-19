package pullrelease

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	restartKey     = "restart"
	restartLease   = 2 * time.Minute
	restartReserve = 30 * time.Second
	meshCaughtUp   = "ok"
)

type restartHold struct {
	Region string    `json:"region,omitempty"`
	Host   string    `json:"host,omitempty"`
	Next   string    `json:"next,omitempty"`
	Until  time.Time `json:"until"`
}

func (s *Store) holdRestart(ctx context.Context, region, host string, quorate bool) (string, error) {
	now := time.Now().UTC()
	mine := restartHold{Region: region, Host: host, Until: now.Add(restartLease)}
	entry, err := s.kv.Get(ctx, restartKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return s.writeRestart(ctx, mine, 0)
	}
	if err != nil {
		return "", err
	}
	var held restartHold
	if err := json.Unmarshal(entry.Value(), &held); err != nil {
		return "", fmt.Errorf("fleet restart lease damaged: %w", err)
	}
	switch {
	case held.Region == region:
		if held.Next != region {
			mine.Next = held.Next
		}
	case held.Region == "" && held.Next == region:
	case !now.Before(held.Until) && !quorate:
		return fmt.Sprintf("fleet restart lease of %s %s expired; not taken over until %s reports every raft group with all replicas current", cmp.Or(held.Region, held.Next), held.Host, host), nil
	case !now.Before(held.Until):
		slog.WarnContext(ctx, "taking over an expired fleet restart lease after a live quorum check", "region", region, "host", host, "expired_region", cmp.Or(held.Region, held.Next), "expired_host", held.Host)
	default:
		owner := cmp.Or(held.Region, held.Next)
		if held.Region != "" && held.Next == "" {
			held.Next = region
			if reason, err := s.writeRestart(ctx, held, entry.Revision()); err != nil || reason != "" {
				return cmp.Or(reason, "fleet restart lease held by "+owner), err
			}
		}
		return fmt.Sprintf("fleet restart lease: %s restarts %s until %s; this region is next", owner, cmp.Or(held.Host, "its JetStream peer"), held.Until.Format(time.RFC3339)), nil
	}
	return s.writeRestart(ctx, mine, entry.Revision())
}

func (s *Store) writeRestart(ctx context.Context, hold restartHold, revision uint64) (string, error) {
	data, err := json.Marshal(hold)
	if err != nil {
		return "", err
	}
	if revision == 0 {
		_, err = s.kv.Create(ctx, restartKey, data)
	} else {
		_, err = s.kv.Update(ctx, restartKey, data, revision)
	}
	if errors.Is(err, jetstream.ErrKeyExists) {
		return "fleet restart lease changed while this region claimed it", nil
	}
	return "", err
}

func (s *Store) releaseRestart(ctx context.Context, region string) error {
	entry, err := s.kv.Get(ctx, restartKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var held restartHold
	if err := json.Unmarshal(entry.Value(), &held); err != nil {
		return fmt.Errorf("fleet restart lease damaged: %w", err)
	}
	if held.Region != region {
		return nil
	}
	if held.Next != "" && held.Next != region {
		reason, err := s.writeRestart(ctx, restartHold{Next: held.Next, Until: time.Now().UTC().Add(restartReserve)}, entry.Revision())
		if err == nil && reason != "" {
			err = errors.New(reason)
		}
		return err
	}
	return s.kv.Delete(ctx, restartKey, jetstream.LastRevision(entry.Revision()))
}

func (u *Updater) claimRestart(ctx context.Context, host string, reply releasepush.Reply) string {
	if !reply.Peer {
		return ""
	}
	if reason := u.settleRestart(ctx); reason != "" && u.status.Restart != host {
		return reason
	}
	reason, err := u.store.holdRestart(ctx, u.Region, host, reply.Mesh == meshCaughtUp)
	if err != nil {
		return "fleet restart lease unavailable: " + err.Error()
	}
	if reason != "" {
		return reason
	}
	if u.status.Restart != host {
		u.status.Restart = host
		if !u.save(ctx) {
			return "pull rollout record changed"
		}
		slog.InfoContext(ctx, "fleet restart lease claimed before a JetStream peer installs", "region", u.Region, "host", host)
	}
	return ""
}

func (u *Updater) settleRestart(ctx context.Context) string {
	held := u.status.Restart
	if held == "" {
		return ""
	}
	if reason := u.caughtUp(ctx, held); reason != "" {
		if _, err := u.store.holdRestart(ctx, u.Region, held, false); err != nil {
			slog.WarnContext(ctx, "fleet restart lease not renewed", "region", u.Region, "host", held, "error", err)
		}
		return reason
	}
	if err := u.store.releaseRestart(ctx, u.Region); err != nil {
		return "fleet restart lease not released: " + err.Error()
	}
	u.status.Restart = ""
	if !u.save(ctx) {
		return "pull rollout record changed"
	}
	slog.InfoContext(ctx, "fleet restart lease released; the JetStream peer caught up", "region", u.Region, "host", held)
	return ""
}

func (u *Updater) caughtUp(ctx context.Context, id string) string {
	name := id
	row := u.status.host(id)
	if row != nil {
		name = row.Host
	}
	reply, err := u.ask(ctx, id, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
	switch {
	case err != nil:
		return name + " does not answer after its restart: " + err.Error()
	case reply.Health == restartPending || reply.State != "" || row != nil && !u.restarted(*row, reply):
		return name + " is restarting"
	case reply.Mesh != meshCaughtUp:
		return name + " is catching up: " + cmp.Or(reply.Mesh, "no mesh health")
	}
	return ""
}

func (u *Updater) restarted(row HostProgress, reply releasepush.Reply) bool {
	onTarget := u.status.Target != nil && reply.Version == u.status.Target.SHA && builds(*u.status.Target, reply.SHA256)
	switch row.State {
	case HostInstalling, HostGating:
		return onTarget
	case HostRestoring:
		return !onTarget
	}
	return true
}

func (s *Store) loadFromLeader(ctx context.Context, region string) (Status, error) {
	request, err := json.Marshal(struct {
		LastBySubject string `json:"last_by_subj"`
	}{"$KV." + Bucket + "." + region})
	if err != nil {
		return Status{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, askWait)
	defer cancel()
	message, err := s.fabric.RequestWithContext(ctx, "$JS.API.STREAM.MSG.GET.KV_"+Bucket, request)
	if err != nil {
		return Status{}, err
	}
	var reply struct {
		Message *struct {
			Data []byte `json:"data"`
		} `json:"message"`
		Error *struct {
			Code        int    `json:"code"`
			Description string `json:"description"`
		} `json:"error"`
	}
	if err := json.Unmarshal(message.Data, &reply); err != nil {
		return Status{}, err
	}
	switch {
	case reply.Error != nil && reply.Error.Code == 404:
		return Status{Region: region, Phase: PhaseIdle}, nil
	case reply.Error != nil:
		return Status{}, errors.New(reply.Error.Description)
	case reply.Message == nil:
		return Status{}, errors.New("stream leader sent no record")
	}
	var status Status
	if err := json.Unmarshal(reply.Message.Data, &status); err != nil {
		return Status{}, fmt.Errorf("pull rollout record damaged: %w", err)
	}
	return status, nil
}
