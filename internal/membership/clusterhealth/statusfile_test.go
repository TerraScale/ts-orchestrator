package clusterhealth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusFileRoundTripsOwnerOnlyAndRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "membership", "cluster-health.json")
	now := time.Now().UTC().Truncate(time.Second)
	file := &StatusFile{Path: path}
	file.ReportClusterHealth(Status{ObservedAt: now, Phase: PhaseHealthy, MetaLeader: "gru-1-ctl-1",
		Online: []string{"gru-1-ctl-1", "gru-1-ctl-2"}, CaughtUp: []string{"gru-1-ctl-2"}})
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("status file = %v, %v", info, err)
	}
	status, err := ReadStatusFile(path)
	if err != nil || !status.ObservedAt.Equal(now) || status.MetaLeader != "gru-1-ctl-1" {
		t.Fatalf("read status = %+v, %v", status, err)
	}
	if err := status.PeerCurrent("gru-1-ctl-2", now.Add(-time.Minute)); err != nil {
		t.Fatalf("current peer: %v", err)
	}
	if err := status.PeerCurrent("gru-1-ctl-3", now.Add(-time.Minute)); err == nil {
		t.Fatal("an absent peer reported current")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatusFile(link); err == nil {
		t.Fatal("a symbolic link was read as the status file")
	}
	if err := WriteStatusFile("relative.json", status); err == nil {
		t.Fatal("a relative status path was written")
	}
}

// Only positive evidence counts as current: an online peer that is merely
// absent from Lagging (lag within the alert threshold, or a follower's view
// of another follower) is not caught up.
func TestPeerCurrentRequiresPositiveCatchUpEvidence(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	leaderView := Observation{ServerName: "gru-1-ctl-1", Running: true, MetaLeader: "gru-1-ctl-1",
		MetaSize: 3, MetaQuorum: 2, Expected: []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"},
		Peers: []Peer{{Name: "gru-1-ctl-2", Current: false, Lag: 500, Active: time.Second},
			{Name: "gru-1-ctl-3", Current: true, Active: time.Second}}}
	status := Evaluate(leaderView, DefaultLagThreshold, now)
	if len(status.Lagging) != 0 {
		t.Fatalf("lagging = %+v; the alert threshold tolerates lag 500", status.Lagging)
	}
	if err := status.PeerCurrent("gru-1-ctl-2", now); err == nil {
		t.Fatal("a peer 500 operations behind reported current")
	}
	if err := status.PeerCurrent("gru-1-ctl-3", now); err != nil {
		t.Fatalf("a peer the leader reports current: %v", err)
	}

	// A follower knows only the leader; it cannot vouch for another follower.
	followerView := Observation{ServerName: "gru-1-ctl-1", Running: true, MetaLeader: "gru-1-ctl-2",
		MetaSize: 3, MetaQuorum: 2, Peers: []Peer{{Name: "gru-1-ctl-2", Current: true, Active: time.Second},
			{Name: "gru-1-ctl-3"}}}
	status = Evaluate(followerView, DefaultLagThreshold, now)
	if err := status.PeerCurrent("gru-1-ctl-3", now); err == nil {
		t.Fatal("a follower vouched for another follower")
	}
	if err := status.PeerCurrent("gru-1-ctl-2", now); err != nil {
		t.Fatalf("the leader a follower heard from: %v", err)
	}
	if err := status.PeerCurrent("gru-1-ctl-2", now.Add(time.Second)); err == nil {
		t.Fatal("a view observed before the cutoff was accepted")
	}
}
