//go:build linux

package host

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/nats-io/nats.go/jetstream"
)

func askTerraBaseFormatTest(t *testing.T, c *Controller, r Registration, query terraBaseFormatQuery) (terraBaseFormatReply, error) {
	t.Helper()
	wire, err := protocol.EncodeJSON(query)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := c.serveTerraBaseFormat(t.Context(), request{Node: r.Node, Payload: wire}, r)
	if err != nil {
		return terraBaseFormatReply{}, err
	}
	return reply.(terraBaseFormatReply), nil
}

func signTerraBaseFormatTest(t *testing.T, cfg VolumeInitConfig, key ed25519.PrivateKey, reply terraBaseFormatReply, issued time.Time) protocol.Envelope {
	t.Helper()
	payload, err := protocol.EncodeJSON(reply)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(response{Nonce: "000000000000ab603a0258fc8d8a26df", Node: cfg.Node, SessionID: "00000000007WXF3V7BQMA11AT1", Epoch: 1,
		Operation: "terrabase-format", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := protocol.SignEnvelope(wire, protocol.EnvelopeScope{Region: cfg.Cell, Kind: "host.response.terrabase-format",
		Actor: "controller", OperationID: entityid.Derive("host-request", "000000000000ab603a0258fc8d8a26df"), Epoch: 1}, issued, issued.Add(requestTTL), key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestTerraBaseDataVolumeLostFormatReplyAndExpiredReplyRecover(t *testing.T) {
	c, _, _, _, controllerKey := testController(t)
	r := Registration{Cell: "gru", Node: "gru-1-db-1", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
		TerraBaseDataVolumeID: "ocid1.volume.oc1..recovery"}
	cfg := VolumeInitConfig{Cell: r.Cell, Node: r.Node, TerraBaseDataVolumeID: r.TerraBaseDataVolumeID,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), StateRoot: t.TempDir()}
	attempt, err := pendingTerraBaseFormatAttempt(cfg)
	if err != nil {
		t.Fatal(err)
	}
	query := terraBaseFormatQuery{VolumeID: r.TerraBaseDataVolumeID, AttemptID: attempt}
	// The CAS succeeds, but the initializer never receives this first reply.
	if _, err := askTerraBaseFormatTest(t, c, r, query); err != nil {
		t.Fatal(err)
	}
	key := terraBaseFormatKey(c.cell, r.Node, r.TerraBaseDataVolumeID)
	var stored terraBaseFormatGrant
	revision, found, err := c.get(t.Context(), key, &stored)
	if err != nil || !found || stored.UUID == "" || stored.AttemptID != attempt || stored.HostKey != r.PublicKey || stored.Generation != r.Generation {
		t.Fatalf("durable grant before lost reply = %+v, found %v, error %v", stored, found, err)
	}
	// A new controller opens the existing file-backed KV; no in-memory grant
	// or original reply is carried over to it.
	js, err := jetstream.New(c.conn)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewController(t.Context(), ControllerConfig{Cell: c.cell, Conn: c.conn, JS: js,
		ControlLog: c.controlLog, Artifacts: c.artifacts, ResponseKey: controllerKey, StateReplicas: 1,
		HostMutations: c.mutations, AuthorityEpoch: c.authorityEpoch, AuthorityGuard: c.authorityGuard})
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := readTerraBaseFormatAttempt(cfg); err != nil || recovered != attempt {
		t.Fatalf("initializer restart attempt = %q, %v; want %s", recovered, err, attempt)
	}
	reply, err := askTerraBaseFormatTest(t, restarted, r, query)
	if err != nil || !reply.Granted || reply.UUID != stored.UUID || reply.AttemptID != attempt {
		t.Fatalf("retry after lost reply = %+v, %v; want the durable grant %+v", reply, err, stored)
	}
	if got, _, err := restarted.get(t.Context(), key, &stored); err != nil || got != revision {
		t.Fatalf("redelivery rewrote grant: revision %d, error %v; want %d", got, err, revision)
	}
	expired := signTerraBaseFormatTest(t, cfg, controllerKey, reply, time.Now().UTC().Add(-time.Minute))
	if _, err := verifyTerraBaseFormatGrant(cfg, expired); !errors.Is(err, protocol.ErrExpired) {
		t.Fatalf("expired signed reply = %v; want expiration", err)
	}
	renewed, err := askTerraBaseFormatTest(t, restarted, r, query)
	if err != nil || !renewed.Granted || renewed.UUID != reply.UUID || renewed.AttemptID != attempt {
		t.Fatalf("renewal after signed reply expiry = %+v, %v; want %+v", renewed, err, reply)
	}
	if uuid, err := verifyTerraBaseFormatGrant(cfg, signTerraBaseFormatTest(t, cfg, controllerKey, renewed, time.Now().UTC())); err != nil || uuid != stored.UUID {
		t.Fatalf("renewed signed reply = %q, %v; want %s", uuid, err, stored.UUID)
	}
	// A wrong attachment may mount a different ext4 UUID. The agent rejects
	// that filesystem; correcting the attachment must preserve this unused grant.
	foreign := terraBaseFormatQuery{VolumeID: r.TerraBaseDataVolumeID, Mounted: "11111111-2222-4333-8444-555555555555"}
	if reported, err := askTerraBaseFormatTest(t, restarted, r, foreign); err != nil || reported.Granted || reported.UUID != stored.UUID {
		t.Fatalf("foreign mounted filesystem = %+v, %v; want recorded UUID %s", reported, err, stored.UUID)
	}
	var afterForeign terraBaseFormatGrant
	if got, found, err := restarted.get(t.Context(), key, &afterForeign); err != nil || !found || got != revision || afterForeign != stored {
		t.Fatalf("foreign filesystem closed pending grant: %+v, revision %d, found %v, error %v", afterForeign, got, found, err)
	}
	if corrected, err := askTerraBaseFormatTest(t, restarted, r, query); err != nil || !corrected.Granted || corrected.UUID != stored.UUID || corrected.AttemptID != attempt {
		t.Fatalf("corrected attachment lost unused grant: %+v, %v", corrected, err)
	}
	query.Mounted = reply.UUID
	query.AttemptID = ""
	if confirmed, err := askTerraBaseFormatTest(t, restarted, r, query); err != nil || confirmed.Granted || confirmed.UUID != reply.UUID {
		t.Fatalf("mounted confirmation = %+v, %v", confirmed, err)
	}
	var confirmedRecord terraBaseFormatGrant
	if got, found, err := restarted.get(t.Context(), key, &confirmedRecord); err != nil || !found || got <= revision || confirmedRecord.AttemptID != "" || confirmedRecord.UUID != reply.UUID {
		t.Fatalf("confirmation did not durably close grant: %+v, revision %d, found %v, error %v", confirmedRecord, got, found, err)
	}
	query.Mounted = ""
	query.AttemptID = attempt
	if closed, err := askTerraBaseFormatTest(t, restarted, r, query); err != nil || closed.Granted || closed.UUID != reply.UUID {
		t.Fatalf("confirmed grant retry = %+v, %v; want refusal", closed, err)
	}
}

func TestTerraBaseDataVolumePendingAttemptPersistsAndFencesRemovedState(t *testing.T) {
	public, controllerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := VolumeInitConfig{Cell: "gru", Node: "gru-1-db-1", StateRoot: t.TempDir(), ControllerPublicKey: public,
		TerraBaseDataVolumeID: "ocid1.volume.oc1..first"}
	if _, err := readTerraBaseFormatAttempt(cfg); err == nil {
		t.Fatal("read created an initializer attempt instead of refusing missing state")
	}
	first, err := pendingTerraBaseFormatAttempt(cfg)
	if err != nil || !entityid.Valid(first) {
		t.Fatalf("pending attempt = %q, %v; want a canonical ULID", first, err)
	}
	if again, err := pendingTerraBaseFormatAttempt(cfg); err != nil || again != first {
		t.Fatalf("pending attempt changed across restart = %q, %v; want %s", again, err, first)
	}
	entries, err := os.ReadDir(cfg.StateRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("pending state files = %v, %v; want one durable marker", entries, err)
	}
	path := filepath.Join(cfg.StateRoot, entries[0].Name())
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("attempt marker mode = %v, %v; want 0600", info, err)
	}
	signed := signTerraBaseFormatTest(t, cfg, controllerKey, terraBaseFormatReply{Granted: true,
		UUID: "0f8fad5b-d9cb-469f-a165-70867728950e", VolumeID: cfg.TerraBaseDataVolumeID, AttemptID: first}, time.Now().UTC())
	if _, err := verifyTerraBaseFormatGrant(cfg, signed); err != nil {
		t.Fatalf("grant matching durable state: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTerraBaseFormatGrant(cfg, signed); err == nil {
		t.Fatal("old grant accepted after original pending state was removed")
	}
	next, err := pendingTerraBaseFormatAttempt(cfg)
	if err != nil || next == first || !entityid.Valid(next) {
		t.Fatalf("replacement pending state = %q, %v; want a fresh attempt", next, err)
	}
	if _, err := verifyTerraBaseFormatGrant(cfg, signed); err == nil {
		t.Fatal("old grant accepted with regenerated pending state and copied host identity")
	}
	other := cfg
	other.TerraBaseDataVolumeID = "ocid1.volume.oc1..second"
	if attempt, err := pendingTerraBaseFormatAttempt(other); err != nil || attempt == next {
		t.Fatalf("another volume shares pending attempt: %q, %v", attempt, err)
	}
	if original, err := readTerraBaseFormatAttempt(cfg); err != nil || original != next {
		t.Fatalf("another volume changed original attempt: %q, %v", original, err)
	}
	if err := os.WriteFile(path, []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTerraBaseFormatAttempt(cfg); err == nil {
		t.Fatal("malformed persisted attempt accepted")
	}
	if _, err := pendingTerraBaseFormatAttempt(cfg); err == nil {
		t.Fatal("malformed persisted attempt silently replaced")
	}
}

func TestTerraBaseDataVolumeLegacyAndClosedRecordsNeverGrant(t *testing.T) {
	c, _, _, _, _ := testController(t)
	const uuid = "0f8fad5b-d9cb-469f-a165-70867728950e"
	const attempt = "014D2PF2DBSQQG28T5CY4TQKFF"
	for _, closed := range []bool{false, true} {
		r := Registration{Cell: "gru", Node: "gru-1-db-1", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
			TerraBaseDataVolumeID: fmt.Sprintf("ocid1.volume.oc1..closed-%v", closed)}
		grant := terraBaseFormatGrant{UUID: uuid}
		if closed {
			grant.HostKey, grant.Generation = r.PublicKey, r.Generation
		}
		if _, err := c.cas(t.Context(), terraBaseFormatKey(c.cell, r.Node, r.TerraBaseDataVolumeID), grant, 0); err != nil {
			t.Fatal(err)
		}
		reply, err := askTerraBaseFormatTest(t, c, r, terraBaseFormatQuery{VolumeID: r.TerraBaseDataVolumeID, AttemptID: attempt})
		if err != nil || reply.Granted || reply.UUID != uuid {
			t.Fatalf("closed=%v grant retry = %+v, %v; want refusal", closed, reply, err)
		}
	}
	for _, attempt := range []string{"", "123", strings.Repeat("a", 33), strings.Repeat("z", 32)} {
		r := Registration{Cell: "gru", Node: "gru-1-db-2", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
			TerraBaseDataVolumeID: "ocid1.volume.oc1..invalid-attempt"}
		if reply, err := askTerraBaseFormatTest(t, c, r, terraBaseFormatQuery{VolumeID: r.TerraBaseDataVolumeID, AttemptID: attempt}); err == nil {
			t.Fatalf("invalid attempt %q accepted: %+v", attempt, reply)
		}
		var grant terraBaseFormatGrant
		if _, found, err := c.get(t.Context(), terraBaseFormatKey(c.cell, r.Node, r.TerraBaseDataVolumeID), &grant); err != nil || found {
			t.Fatalf("invalid attempt %q changed grant state: %+v, found %v, error %v", attempt, grant, found, err)
		}
	}
}

func TestTerraBaseDataVolumeDurableConsumptionSurvivesRestart(t *testing.T) {
	for _, crash := range []string{"before mkfs", "after mkfs", "lost mounted acknowledgment"} {
		t.Run(crash, func(t *testing.T) {
			c, _, _, _, controllerKey := testController(t)
			r := Registration{Cell: "gru", Node: "gru-1-db-1", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
				TerraBaseDataVolumeID: "ocid1.volume.oc1..consumption"}
			cfg := VolumeInitConfig{Cell: r.Cell, Node: r.Node, StateRoot: t.TempDir(), TerraBaseDataVolumeID: r.TerraBaseDataVolumeID,
				ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey)}
			attempt, err := pendingTerraBaseFormatAttempt(cfg)
			if err != nil {
				t.Fatal(err)
			}
			query := terraBaseFormatQuery{VolumeID: r.TerraBaseDataVolumeID, AttemptID: attempt}
			reply, err := askTerraBaseFormatTest(t, c, r, query)
			if err != nil || !reply.Granted {
				t.Fatalf("first format grant = %+v, %v", reply, err)
			}
			signed := signTerraBaseFormatTest(t, cfg, controllerKey, reply, time.Now().UTC())
			uuid, err := verifyTerraBaseFormatGrant(cfg, signed)
			if err != nil {
				t.Fatal(err)
			}
			marker := terraBaseFormatMarkerPath(cfg)
			probe := volumeFilesystemProbe{BlankSample: true}
			var calls []string
			formats := 0
			crashErr := errors.New("initializer process interrupted")
			effects := volumeInitEffects{
				Consume: func() error {
					calls = append(calls, "consume")
					if err := createDurableMarker(marker, []byte(uuid+"\n")); err != nil {
						return err
					}
					if crash == "before mkfs" {
						return crashErr
					}
					return nil
				},
				Format: func(context.Context) error {
					calls = append(calls, "format")
					if data, err := os.ReadFile(marker); err != nil || string(data) != uuid+"\n" {
						t.Fatalf("mkfs ran before durable consumption: %q, %v", data, err)
					}
					formats++
					probe = volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4", Signatures: true}
					if crash == "after mkfs" {
						return crashErr
					}
					return nil
				},
				Probe: func(context.Context) (volumeFilesystemProbe, error) {
					calls = append(calls, "probe")
					return probe, nil
				},
				Mount: func(context.Context, bool) error { calls = append(calls, "mount"); return nil },
			}
			err = executeTerraBaseVolume(t.Context(), probe, uuid, signed.ExpiresAt, false, effects)
			want := "consume,format,probe,mount"
			if crash == "before mkfs" {
				want = "consume"
			} else if crash == "after mkfs" {
				want = "consume,format"
			}
			if strings.Join(calls, ",") != want || (crash != "lost mounted acknowledgment" && !errors.Is(err, crashErr)) ||
				(crash == "lost mounted acknowledgment" && err != nil) {
				t.Fatalf("first effects = %v, error %v; want %s", calls, err, want)
			}
			// Rebuild consumption solely from the root marker, as a restarted
			// initializer does, while the controller still has a pending grant.
			if data, err := os.ReadFile(marker); err != nil || string(data) != uuid+"\n" {
				t.Fatalf("restart lost consumption marker: %q, %v", data, err)
			}
			again, err := askTerraBaseFormatTest(t, c, r, query)
			if err != nil || !again.Granted || again.UUID != uuid || again.AttemptID != attempt {
				t.Fatalf("grant without mounted acknowledgment = %+v, %v", again, err)
			}
			renewed := signTerraBaseFormatTest(t, cfg, controllerKey, again, time.Now().UTC())
			if replayUUID, err := verifyTerraBaseFormatGrant(cfg, renewed); err != nil || replayUUID != uuid {
				t.Fatalf("redelivered grant verification = %q, %v; want %s", replayUUID, err, uuid)
			}
			calls = nil
			_, markerErr := os.Lstat(marker)
			err = executeTerraBaseVolume(t.Context(), probe, "", time.Time{}, markerErr == nil, effects)
			if crash == "before mkfs" {
				if err == nil || errors.Is(err, errFormatGrantNeeded) || len(calls) != 0 || formats != 0 {
					t.Fatalf("consumed blank restart = %v, effects %v, formats %d; want hold without another grant request", err, calls, formats)
				}
			} else if err != nil || strings.Join(calls, ",") != "mount" || formats != 1 {
				t.Fatalf("formatted restart = %v, effects %v, formats %d; want mount with one total format", err, calls, formats)
			}
			// Even if the disk becomes blank and a freshly signed redelivery
			// verifies, the durable local marker prevents every replayed mkfs.
			calls = nil
			err = executeTerraBaseVolume(t.Context(), volumeFilesystemProbe{BlankSample: true}, again.UUID,
				renewed.ExpiresAt, markerErr == nil, effects)
			if err == nil || errors.Is(err, errFormatGrantNeeded) || len(calls) != 0 || formats > 1 {
				t.Fatalf("replayed grant on consumed blank = %v, effects %v, formats %d", err, calls, formats)
			}
		})
	}
}

func TestTerraBaseDataVolumeGrantFramingRejectsInvalidAttempt(t *testing.T) {
	for _, token := range []string{"", "0123456789abcdef", strings.Repeat("z", 32)} {
		t.Run(fmt.Sprintf("token-%d-%s", len(token), token), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			go func() {
				defer server.Close()
				var size [4]byte
				if _, err := io.ReadFull(server, size[:]); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint32(size[:]))); err != nil {
					return
				}
				_, _ = server.Write(append([]byte{volumeInitNeedsGrant}, token...))
			}()
			err := exchangeVolumeInit(client, terraBaseDataRequest)
			var needed terraBaseFormatNeeded
			if err == nil || errors.Is(err, errFormatGrantNeeded) || errors.As(err, &needed) {
				t.Fatalf("invalid attempt token %q yielded grant authority: %v", token, err)
			}
		})
	}
}
