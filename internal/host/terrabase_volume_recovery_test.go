//go:build linux

package host

import (
	"context"
	"crypto/ed25519"

	"errors"

	"os"

	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
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
