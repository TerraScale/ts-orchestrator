package controltransition

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"
)

func TestRestoreReceiptRequiresExactFinalInventoryAndSignedPredecessors(t *testing.T) {
	p := testPlan(t)
	p.IssuedAt = time.Now().UTC().Add(-time.Minute)
	p.ExpiresAt = p.IssuedAt.Add(time.Hour)
	owner, ownerPublic := testKey(t)
	source, sourcePublic := testKey(t)
	destination, destinationPublic := testKey(t)
	p.Source.ReceiptPublicKeyPEM = string(sourcePublic)
	p.Destinations[0].ReceiptPublicKeyPEM = string(destinationPublic)
	signedPlan, err := SignPlan(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyPlan(ownerPublic, signedPlan)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	h := strings.Repeat("d", 64)
	state := SourceStateReceipt{Version: 1, Phase: "source-quiesced", PlanSHA256: v.Digest(), NodeID: p.Source.NodeID, QuiescedAt: now.Add(-5 * time.Second), ObservedAt: now.Add(-4 * time.Second), GlobalElectionFloor: p.GlobalElectionFloor, RegionalElectionFloor: p.RegionalElectionFloor, Streams: []StreamEvidence{}}
	for _, account := range p.Accounts {
		for _, stream := range account.Streams {
			e := StreamEvidence{Role: account.Role, Account: account.SourceName, Stream: stream.Name, Created: now.Add(-30 * time.Second), ConfigSHA256: stream.SourceConfigSHA256, RecordsSHA256: h, StateSHA256: h, Consumers: []ConsumerEvidence{}}
			for _, consumer := range stream.Consumers {
				e.Consumers = append(e.Consumers, ConsumerEvidence{Name: consumer.Name, Created: now.Add(-20 * time.Second), Durable: consumer.Durable, ConfigSHA256: consumer.SourceConfigSHA256, CheckpointSHA256: h})
			}
			state.Streams = append(state.Streams, e)
		}
	}
	stateRaw, err := SignSourceStateReceipt(source, v, state)
	if err != nil {
		t.Fatal(err)
	}
	cut := CutReceipt{Version: 1, Phase: "source-store-copied", PlanSHA256: v.Digest(), NodeID: p.Source.NodeID, BootstrapGrantSHA256: p.Source.BootstrapGrantSHA256, StoreScopeSHA256: p.Source.StoreScopeSHA256, StoreSHA256: h, CopySHA256: h, SourceDevice: 1, SourceInode: 1, Files: 1, Bytes: 100, StoppedAt: now.Add(-3 * time.Second), CopiedAt: now.Add(-2 * time.Second)}
	cutRaw, err := SignCutReceipt(source, v, cut)
	if err != nil {
		t.Fatal(err)
	}
	capture := CaptureReceipt{Version: 1, Phase: "final-capture", PlanSHA256: v.Digest(), CutReceiptSHA256: Digest(cutRaw), SourceStateReceiptSHA256: Digest(stateRaw), NodeID: p.Source.NodeID, StoreSHA256: h, CopySHA256: h, CapturedAt: now.Add(-time.Second), GlobalElectionFloor: state.GlobalElectionFloor, RegionalElectionFloor: state.RegionalElectionFloor, Streams: state.Streams, Objects: []CaptureObject{}}
	for _, e := range state.Streams {
		key, err := CaptureObjectKey(v, e.Role, e.Stream)
		if err != nil {
			t.Fatal(err)
		}
		capture.Objects = append(capture.Objects, CaptureObject{Role: e.Role, Stream: e.Stream, Key: key, SHA256: h, Size: 1024})
	}
	captureRaw, err := SignCaptureReceipt(source, v, cutRaw, stateRaw, capture)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RestoreReceipt{Version: 1, Phase: "final-restored-r3", PlanSHA256: v.Digest(), CaptureReceiptSHA256: Digest(captureRaw), NodeID: p.Destinations[0].NodeID, Cluster: p.ClusterName, GlobalElectionFloor: state.GlobalElectionFloor, RegionalElectionFloor: state.RegionalElectionFloor, RestoredAt: now, Streams: []RestoredStream{}}
	index := 0
	for _, account := range p.Accounts {
		for _, stream := range account.Streams {
			e := state.Streams[index]
			index++
			e.Account = account.DestinationName
			e.Created = now
			e.ConfigSHA256 = stream.FinalConfigSHA256
			e.Consumers = append([]ConsumerEvidence{}, e.Consumers...)
			for i := range e.Consumers {
				e.Consumers[i].ConfigSHA256 = stream.Consumers[i].FinalConfigSHA256
			}
			receipt.Streams = append(receipt.Streams, RestoredStream{SourceCreated: state.Streams[index-1].Created, Observed: e, Servers: []string{"fra-r3", "gru-r3", "sfo-r3"}})
		}
	}
	raw, err := SignRestoreReceipt(destination, v, cutRaw, stateRaw, captureRaw, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRestoreReceipt(v, cutRaw, stateRaw, captureRaw, raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RestoreReceipt){
		"preliminary":      func(r *RestoreReceipt) { r.Phase = "preliminary-restored" },
		"wrong capture":    func(r *RestoreReceipt) { r.CaptureReceiptSHA256 = h },
		"missing stream":   func(r *RestoreReceipt) { r.Streams = r.Streams[:len(r.Streams)-1] },
		"wrong peer":       func(r *RestoreReceipt) { r.Streams[0].Servers[0] = "foreign" },
		"record drift":     func(r *RestoreReceipt) { r.Streams[0].Observed.RecordsSHA256 = strings.Repeat("e", 64) },
		"consumer created": func(r *RestoreReceipt) { r.Streams[1].Observed.Consumers[0].Created = now },
		"checkpoint drift": func(r *RestoreReceipt) { r.Streams[1].Observed.Consumers[0].CheckpointSHA256 = strings.Repeat("e", 64) },
		"floor regression": func(r *RestoreReceipt) { r.GlobalElectionFloor-- },
	} {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			var changed RestoreReceipt
			if err := json.Unmarshal(body, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if _, err := SignRestoreReceipt(destination, v, cutRaw, stateRaw, captureRaw, changed); err == nil {
				t.Fatal("conflicting receipt signed")
			}
		})
	}
	if _, err := SignRestoreReceipt(source, v, cutRaw, stateRaw, captureRaw, receipt); err == nil {
		t.Fatal("source signed destination completion")
	}
	if _, err := VerifyRestoreReceipt(v, cutRaw, raw, captureRaw, raw); err == nil {
		t.Fatal("wrong predecessor accepted")
	}
}
