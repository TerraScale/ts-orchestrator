package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

func mutationTestRuntime(t *testing.T) (*NATSControlRuntime, *nats.Conn, jetstream.KeyValue, authority.RegionalAuthorityLeaseDocument, ControlRuntimeActionPlan) {
	t.Helper()
	cluster := newControlMutationStateCluster(t)
	nc := cluster.connect(t)
	kv := openControlMutationTestLeaseStore(t, t.Context(), nc, true)
	lease := controlMutationTestLease(7, "global-controller-gru-one")
	putControlMutationTestLease(t, t.Context(), kv, lease)
	store := ControlNATSStore{URL: nc.ConnectedUrl(), Options: []nats.Option{nats.Secure(cluster.tls.Clone()), nats.Nkey(cluster.public, cluster.key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1)}}
	r := &NATSControlRuntime{config: NATSControlRuntimeConfig{Stores: map[string]ControlNATSStore{"target": store, "source": store}}, members: map[string]ControlRuntimeMember{"one": {Region: "gru", Instance: "one", ServerName: "controlMutation-0", Store: "target"}}}
	plan := ControlRuntimeActionPlan{Kind: ControlActionPromoteR3, Region: "gru", ExpectedEpoch: 1, TargetEpoch: 2, ReplicaUpdates: []ControlReplicaPlan{{Store: "target", Streams: []string{"FIRST", "SECOND"}, Replicas: 3}}, Checks: []ControlStoreCheck{{Store: "target", Region: "gru", AuthorityID: "global", AuthorityTerm: uint64(lease.Epoch), AuthorityCandidateID: lease.CandidateId, AuthorityLeaseID: lease.LeaseId, LeaseKey: "authority.global", Streams: []ControlStreamAssignment{{Name: "FIRST", Replicas: 3, Servers: []string{"controlMutation-0"}}}}}}
	return r, nc, kv, lease, plan
}
func TestControlMutationPinsRejectReplacementAcrossRuntimeReconstruction(t *testing.T) {
	r, nc, kv, lease, plan := mutationTestRuntime(t)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := r.controlMutationPins(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkControlMutation(t.Context(), js, "target", pins); err != nil {
		t.Fatal(err)
	}
	lease.IssuedAt = time.Now().UTC()
	putControlMutationTestLease(t, t.Context(), kv, lease)
	if err := checkControlMutation(t.Context(), js, "target", pins); err != nil {
		t.Fatalf("same identity renewal refused: %v", err)
	}
	lease.LeaseId = "replacement-same-term"
	putControlMutationTestLease(t, t.Context(), kv, lease)
	reconstructed := &NATSControlRuntime{config: r.config, members: r.members}
	pins, err = reconstructed.controlMutationPins(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkControlMutation(t.Context(), js, "target", pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("same-term lease adopted after reconstruction: %v", err)
	}
	lease.LeaseId = plan.Checks[0].AuthorityLeaseID
	lease.CandidateId = "global-controller-gru-other"
	putControlMutationTestLease(t, t.Context(), kv, lease)
	if err := checkControlMutation(t.Context(), js, "target", pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("replacement candidate admitted: %v", err)
	}
	for _, edit := range []func(*ControlRuntimeActionPlan){func(p *ControlRuntimeActionPlan) { p.Checks[0].AuthorityLeaseID = "" }, func(p *ControlRuntimeActionPlan) { p.Checks[0].AuthorityCandidateID = "global-controller-gru-other" }, func(p *ControlRuntimeActionPlan) { p.Checks = nil }} {
		raw, _ := json.Marshal(plan)
		var bad ControlRuntimeActionPlan
		json.Unmarshal(raw, &bad)
		edit(&bad)
		if _, err := r.controlMutationPins(bad); err == nil {
			t.Fatal("mutation without exact admitted identity accepted")
		}
	}
}
func TestControlReplicaMutationRechecksLeaseBetweenActualUpdates(t *testing.T) {
	r, nc, kv, lease, plan := mutationTestRuntime(t)
	ctx := t.Context()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"FIRST", "SECOND"} {
		if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: name, Subjects: []string{name}, Storage: jetstream.FileStorage, Replicas: 1, MaxBytes: 4096}); err != nil {
			t.Fatal(err)
		}
	}
	pins, err := r.controlMutationPins(plan)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	traced, err := jetstream.New(nc, jetstream.WithClientTrace(&jetstream.ClientTrace{ResponseReceived: func(subject string, _ []byte, _ nats.Header) {
		if subject == "$JS.API.STREAM.UPDATE.FIRST" && !changed {
			changed = true
			lease.IssuedAt = time.Now().UTC().Add(-time.Second)
			lease.DurationMilliseconds = 1
			putControlMutationTestLease(t, ctx, kv, lease)
		}
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := updateControlReplicaStreams(ctx, traced, plan.ReplicaUpdates[0], pins); !errors.Is(err, ErrControlMutationUnknown) {
		t.Fatalf("multi-update expiry: %v", err)
	}
	if !changed {
		t.Fatal("first real stream update was not observed")
	}
	for _, item := range []struct {
		name     string
		replicas int
	}{{"FIRST", 3}, {"SECOND", 1}} {
		stream, err := js.Stream(ctx, item.name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := stream.Info(ctx)
		if err != nil || info.Config.Replicas != item.replicas {
			t.Fatalf("replicas after expiry %s: %+v %v", item.name, info, err)
		}
	}
	// The same declared retry cannot mutate SECOND under an expired lease.
	if err := r.updateControlReplicas(ctx, plan.ReplicaUpdates[0], pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("expired retry authorized: %v", err)
	}
}
func TestControlMirrorUsesFiniteSourceProfileAndRejectsUnboundedReplay(t *testing.T) {
	r, nc, kv, lease, plan := mutationTestRuntime(t)
	ctx := t.Context()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	source, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "SOURCE", Subjects: []string{"source.>"}, Storage: jetstream.FileStorage, Replicas: 1, MaxBytes: 8192, MaxMsgs: 10, MaxMsgsPerSubject: 2, MaxMsgSize: 1024, Discard: jetstream.DiscardNew})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := source.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mirror := ControlMirrorPlan{Store: "target", Name: "MIRROR_SOURCE", SourceStore: "source", SourceStream: "SOURCE"}
	plan.ReplicaUpdates = nil
	plan.MirrorUpdates = []ControlMirrorPlan{mirror}
	pins, err := r.controlMutationPins(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.createMirror(ctx, mirror, pins); err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, mirror.Name)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.MaxBytes != 8192 || !matchesControlMirror(info.Config, mirror, profile.Config) {
		t.Fatalf("mirror lost finite source bounds: %+v", info.Config)
	}
	if err := r.createMirror(ctx, mirror, pins); err != nil {
		t.Fatalf("same mirror retry: %v", err)
	}
	altered := info.Config
	altered.MaxBytes = -1
	if _, err := js.UpdateStream(ctx, altered); err != nil {
		t.Fatal(err)
	}
	if err := r.createMirror(ctx, mirror, pins); err == nil {
		t.Fatal("unbounded existing mirror admitted")
	}
	lease.LeaseId = "replacement"
	putControlMutationTestLease(t, ctx, kv, lease)
	mirror.Name = "FENCED_MIRROR"
	if err := r.createMirror(ctx, mirror, pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("fenced mirror create: %v", err)
	}
	if _, err := js.Stream(ctx, mirror.Name); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("fenced mirror exists: %v", err)
	}
	unbounded := profile.Config
	unbounded.MaxBytes = -1
	if _, err := controlMirrorConfig(mirror, unbounded); err == nil {
		t.Fatal("unbounded source accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := checkControlMutation(canceled, js, "target", pins); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestControlMirrorRejectsFilteredTruncatedOrTransformedInventory(t *testing.T) {
	source := jetstream.StreamConfig{Name: "SOURCE", Storage: jetstream.FileStorage, MaxBytes: 8192, MaxMsgs: -1, MaxMsgsPerSubject: -1, MaxMsgSize: -1}
	plan := ControlMirrorPlan{Name: "MIRROR", SourceStream: "SOURCE", ExternalAPIPrefix: "$JS.admitted.API"}
	valid, err := controlMirrorConfig(plan, source)
	if err != nil {
		t.Fatal(err)
	}
	if !matchesControlMirror(valid, plan, source) {
		t.Fatal("exact mirror refused")
	}
	now := time.Now().UTC()
	cases := map[string]func(*jetstream.StreamConfig){
		"start sequence": func(c *jetstream.StreamConfig) { c.Mirror.OptStartSeq = 10 },
		"start time":     func(c *jetstream.StreamConfig) { c.Mirror.OptStartTime = &now },
		"filter":         func(c *jetstream.StreamConfig) { c.Mirror.FilterSubject = "only.some" },
		"source transform": func(c *jetstream.StreamConfig) {
			c.Mirror.SubjectTransforms = []jetstream.SubjectTransformConfig{{Source: ">", Destination: "changed.>"}}
		},
		"delivery redirect": func(c *jetstream.StreamConfig) { c.Mirror.External.DeliverPrefix = "other" },
		"domain":            func(c *jetstream.StreamConfig) { c.Mirror.Domain = "other" },
		"consumer redirect": func(c *jetstream.StreamConfig) {
			c.Mirror.Consumer = &jetstream.StreamConsumerSource{Name: "other", DeliverSubject: "other"}
		},
		"stream transform": func(c *jetstream.StreamConfig) {
			c.SubjectTransform = &jetstream.SubjectTransformConfig{Source: ">", Destination: "changed.>"}
		},
		"republication": func(c *jetstream.StreamConfig) {
			c.RePublish = &jetstream.RePublish{Source: ">", Destination: "changed.>"}
		},
		"subjects":            func(c *jetstream.StreamConfig) { c.Subjects = []string{"injected.>"} },
		"first sequence":      func(c *jetstream.StreamConfig) { c.FirstSeq = 10 },
		"seal":                func(c *jetstream.StreamConfig) { c.Sealed = true },
		"rollup":              func(c *jetstream.StreamConfig) { c.AllowRollup = true },
		"message ttl":         func(c *jetstream.StreamConfig) { c.AllowMsgTTL = true },
		"delete markers":      func(c *jetstream.StreamConfig) { c.SubjectDeleteMarkerTTL = time.Second },
		"counter":             func(c *jetstream.StreamConfig) { c.AllowMsgCounter = true },
		"schedules":           func(c *jetstream.StreamConfig) { c.AllowMsgSchedules = true },
		"atomic publish":      func(c *jetstream.StreamConfig) { c.AllowAtomicPublish = true },
		"batch publish":       func(c *jetstream.StreamConfig) { c.AllowBatchPublish = true },
		"per subject discard": func(c *jetstream.StreamConfig) { c.DiscardNewPerSubject = true },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			bad, err := controlMirrorConfig(plan, source)
			if err != nil {
				t.Fatal(err)
			}
			edit(&bad)
			if matchesControlMirror(bad, plan, source) {
				t.Fatal("forged inventory admitted")
			}
		})
	}
}
func TestControlGlobalMutationAndEvidenceRejectNonGRUApplicationAuthority(t *testing.T) {
	r, _, kv, lease, plan := mutationTestRuntime(t)
	r.members["sfo"] = ControlRuntimeMember{Region: "sfo", Instance: "sfo-one", ServerName: "sfo-server", Store: "target"}
	plan.Checks[0].Streams[0].Servers = append(plan.Checks[0].Streams[0].Servers, "sfo-server")
	plan.Checks[0].AuthorityCandidateID = "global-controller-sfo-sfo-one"
	if _, err := r.controlMutationPins(plan); err == nil {
		t.Fatal("SFO replica admitted as global mutation authority")
	}
	lease.CandidateId = plan.Checks[0].AuthorityCandidateID
	putControlMutationTestLease(t, t.Context(), kv, lease)
	// The real leader lease is valid and the holder is an admitted storage peer,
	// but neither declaration validation nor store evidence may confer GRU authority.
	if _, _, _, err := r.checkStore(t.Context(), plan.Checks[0]); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("SFO global evidence: %v", err)
	}
}
