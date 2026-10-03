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
	file.ReportClusterHealth(Status{ObservedAt: now, Phase: PhaseHealthy, MetaLeader: "gru-controller-a",
		Online: []string{"gru-controller-a", "gru-controller-b"}})
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("status file = %v, %v", info, err)
	}
	status, err := ReadStatusFile(path)
	if err != nil || !status.ObservedAt.Equal(now) || status.MetaLeader != "gru-controller-a" {
		t.Fatalf("read status = %+v, %v", status, err)
	}
	if err := status.PeerCurrent("gru-controller-b", now.Add(-time.Minute)); err != nil {
		t.Fatalf("current peer: %v", err)
	}
	if err := status.PeerCurrent("gru-controller-c", now.Add(-time.Minute)); err == nil {
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
