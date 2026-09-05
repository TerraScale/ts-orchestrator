package hostagent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"
)

type stalledArtifactDownloader struct {
	next    ArtifactDownloader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (d *stalledArtifactDownloader) Download(ctx context.Context, url, target string, maximum int64) error {
	d.once.Do(func() { close(d.started) })
	select {
	case <-d.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return d.next.Download(ctx, url, target, maximum)
}

func TestStatusReportsUnknownDuringBlockedArtifactDownload(t *testing.T) {
	h := newTestHarness(t)
	spec := h.publish(t, "terrabase", "1.0.0")
	if err := h.lifecycle.HydrateDesired([]hostmanifest.ComponentSpec{spec}); err != nil {
		t.Fatal(err)
	}
	_, connection, _ := newTestTransport(t, h)
	signature := h.releases[spec.SignatureURL]
	h.releases[spec.SignatureURL] = []byte("invalid-signature-sensitive-provider-detail")
	if err := h.lifecycle.ApplyDesired(context.Background(), []hostmanifest.ComponentSpec{spec}); err == nil {
		t.Fatal("bad signature accepted")
	}
	h.releases[spec.SignatureURL] = signature

	download := &stalledArtifactDownloader{next: h.lifecycle.installer.downloader, started: make(chan struct{}), release: make(chan struct{})}
	h.lifecycle.installer.downloader = download
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- h.lifecycle.ApplyDesired(ctx, []hostmanifest.ComponentSpec{spec}) }()
	select {
	case <-download.started:
	case <-time.After(time.Second):
		t.Fatal("download did not start")
	}
	reply := make(chan []byte, 1)
	go func() {
		data, _ := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain-status", mustJSON(t, NodeStatusRequest{CommandId: "while-installing"}))
		reply <- data
	}()
	select {
	case data := <-reply:
		var envelope CommandEnvelopeError
		if err := json.Unmarshal(data, &envelope); err != nil || !strings.HasPrefix(envelope.Detail, errHostObservationBusy.Error()) {
			t.Fatalf("busy installation claimed status: %s %v", data, err)
		}
		if !strings.Contains(envelope.Detail, "last-failed-phase=signature-read") || strings.Contains(envelope.Detail, "sensitive-provider-detail") {
			t.Fatalf("retry lost its safe failure phase: %s", envelope.Detail)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("status queued behind an artifact download")
	}
	close(download.release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	data, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain-status", mustJSON(t, NodeStatusRequest{CommandId: "after-installing"}))
	if err != nil {
		t.Fatal(err)
	}
	var status NodeStatusReport
	if err := json.Unmarshal(data, &status); err != nil || len(status.Facts.Components) != 1 || !status.Facts.Components[0].Installed {
		t.Fatalf("completed release was not authenticated: %s %v", data, err)
	}
}

func TestStatusDoesNotQueueBehindAnotherMutationCommand(t *testing.T) {
	h := newTestHarness(t)
	transport, connection, _ := newTestTransport(t, h)
	transport.commandMutex.Lock()
	defer transport.commandMutex.Unlock()
	data, err := connection.request("ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain-status", mustJSON(t, NodeStatusRequest{CommandId: "while-mutating"}))
	var envelope CommandEnvelopeError
	if err != nil || json.Unmarshal(data, &envelope) != nil || !strings.HasPrefix(envelope.Detail, errHostObservationBusy.Error()) {
		t.Fatalf("busy mutation did not refuse observation: %s %v", data, err)
	}
}
