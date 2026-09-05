package initialcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// PreliminaryCaptureStatus reports local source staging only. Complete does
// not assert a stopped-source cut, a destination restore, or synchronization.
type PreliminaryCaptureStatus struct {
	State           string `json:"state"`
	RequestSHA256   string `json:"requestSha256,omitempty"`
	TransitionID    string `json:"transitionId,omitempty"`
	CapturedStreams int    `json:"capturedStreams,omitempty"`
	TotalStreams    int    `json:"totalStreams,omitempty"`
	ReceiptSHA256   string `json:"receiptSha256,omitempty"`
	Error           string `json:"error,omitempty"`
}

type preliminaryWorker struct {
	done   chan struct{}
	mu     sync.Mutex
	status PreliminaryCaptureStatus
}

// PreliminaryInventory is the ordered account inventory shared by the signed
// request producer and source worker; stream names come from the exact profile.
func PreliminaryInventory(cell, instance, regionalAccount, globalAccount string) ([]preliminarycapture.AccountInventory, error) {
	if regionalAccount == "" || globalAccount == "" || regionalAccount == globalAccount {
		return nil, errors.New("initial control: distinct capture accounts required")
	}
	p, err := buildProfiles(cell, instance)
	if err != nil {
		return nil, err
	}
	return []preliminarycapture.AccountInventory{{Account: regionalAccount, Streams: captureStreamNames(p.Regional)}, {Account: globalAccount, Streams: captureStreamNames(p.Global)}}, nil
}

func (r *Runtime) PreliminaryCapture() PreliminaryCaptureStatus {
	if r == nil || r.capture == nil {
		return PreliminaryCaptureStatus{State: "disabled"}
	}
	r.capture.mu.Lock()
	defer r.capture.mu.Unlock()
	return r.capture.status
}

func (w *preliminaryWorker) setStatus(s PreliminaryCaptureStatus) {
	w.mu.Lock()
	w.status = s
	w.mu.Unlock()
}

func startPreliminaryWorker(ctx context.Context, admission *initialgrant.Admission, global func() authority.RegionalAuthoritySnapshot) *preliminaryWorker {
	w := &preliminaryWorker{done: make(chan struct{}), status: PreliminaryCaptureStatus{State: "idle"}}
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var completed []byte
		var completedStatus PreliminaryCaptureStatus
		for {
			if ctx.Err() != nil {
				return
			}
			raw, err := initialgrant.ReadPreliminaryRequest(admission.Config().PreliminaryCapture.RequestFile)
			if err == nil {
				if bytes.Equal(raw, completed) {
					verified, verifyErr := admission.VerifyPreliminaryRequest(ctx, raw)
					err = verifyErr
					if err == nil {
						err = captureAuthority(global, verified.Request.ControlEpoch)
					}
					if err == nil {
						w.setStatus(completedStatus)
					}
				} else {
					err = w.capture(ctx, admission, global, raw)
					if err == nil {
						completed = append([]byte(nil), raw...)
						w.mu.Lock()
						completedStatus = w.status
						w.mu.Unlock()
					}
				}
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "capture diagnostic: %v\n", err)
				w.mu.Lock()
				w.status.State = "failed"
				// Error text is deliberately fixed: request contents and credential
				// paths are not copied into the externally consumed status.
				w.status.Error = "preliminary capture refused or incomplete"
				w.mu.Unlock()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return w
}

func captureAuthority(global func() authority.RegionalAuthoritySnapshot, epoch uint64) error {
	snapshot := global()
	if !snapshot.Ready() || !snapshot.IsLeader || snapshot.State != "leader" || snapshot.Epoch <= 0 || uint64(snapshot.Epoch) != epoch {
		return errors.New("initial control: preliminary capture requires the admitted live global term")
	}
	return nil
}

func (w *preliminaryWorker) capture(ctx context.Context, admission *initialgrant.Admission, global func() authority.RegionalAuthoritySnapshot, raw []byte) error {
	verified, err := admission.VerifyPreliminaryRequest(ctx, raw)
	if err != nil {
		return err
	}
	cfg := admission.Config()
	profiles, err := buildProfiles(cfg.Cell, cfg.SeedInstance)
	if err != nil {
		return err
	}
	if !equalStrings(verified.Request.Accounts[0].Streams, captureStreamNames(profiles.Regional)) || !equalStrings(verified.Request.Accounts[1].Streams, captureStreamNames(profiles.Global)) {
		return errors.New("initial control: preliminary inventory differs from complete initial profile")
	}
	if err := captureAuthority(global, verified.Request.ControlEpoch); err != nil {
		return err
	}
	status := PreliminaryCaptureStatus{State: "capturing", RequestSHA256: verified.Digest, TransitionID: verified.Request.TransitionID}
	for _, account := range verified.Request.Accounts {
		status.TotalStreams += len(account.Streams)
	}
	w.setStatus(status)
	operation, cancel := context.WithDeadline(ctx, verified.Request.ExpiresAt)
	defer cancel()
	bounded, stop := context.WithTimeout(operation, 10*time.Minute)
	defer stop()
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-bounded.Done():
				return
			case <-ticker.C:
				if verified.Check(time.Now().UTC()) != nil || captureAuthority(global, verified.Request.ControlEpoch) != nil {
					stop()
					return
				}
			}
		}
	}()
	defer func() { stop(); <-monitorDone }()
	return admission.WithinMutation(bounded, func(op context.Context) error {
		return w.captureAdmitted(op, cfg, verified, raw, global, status)
	})
}

func (w *preliminaryWorker) captureAdmitted(ctx context.Context, cfg initialgrant.Config, verified preliminarycapture.VerifiedRequest, raw []byte, global func() authority.RegionalAuthoritySnapshot, status PreliminaryCaptureStatus) error {
	settings := cfg.PreliminaryCapture
	store, err := preliminarycapture.NewStore(preliminarycapture.StoreConfig{Context: ctx, OutputDir: settings.OutputDir, Request: verified, SignedRequest: raw, MaxSnapshotBytes: settings.MaxSnapshotBytes, MaxTotalBytes: settings.MaxTotalBytes})
	if err != nil {
		return err
	}
	defer store.Close()
	public, err := base64.StdEncoding.Strict().DecodeString(cfg.Membership.PublicKey)
	if err != nil {
		return err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})
	if receiptRaw, found, err := store.ReadReceipt(); err != nil {
		return err
	} else if found {
		receipt, err := preliminarycapture.VerifyReceipt(publicPEM, receiptRaw)
		if err != nil || receipt.RequestSHA256 != verified.Digest || receipt.SourceNodeID != cfg.NodeID || receipt.ControlEpoch != verified.Request.ControlEpoch {
			return errors.New("initial control: existing preliminary receipt differs")
		}
		return w.completeCapture(ctx, global, verified.Request.ControlEpoch, status, receiptRaw)
	}
	var objects []preliminarycapture.Object
	for index, account := range verified.Request.Accounts {
		identity := settings.Regional
		if index == 1 {
			identity = settings.Global
		}
		connection, err := connect(ctx, cfg.Broker, identity)
		if err != nil {
			return err
		}
		captured, err := captureAccount(ctx, connection, store, account, verified, settings.MaxSnapshotBytes, func() {
			status.CapturedStreams++
			w.setStatus(status)
		})
		connection.Close()
		if err != nil {
			return err
		}
		objects = append(objects, captured...)
	}
	if err := captureAuthority(global, verified.Request.ControlEpoch); err != nil {
		return err
	}
	key, err := readCredential(cfg.Membership.SigningKeyFile, "", true)
	if err != nil {
		return err
	}
	signer, err := security.ParseCommandSignatureSignerPEM(key)
	clear(key)
	if err != nil {
		return err
	}
	defer signer.Close()
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, RequestSHA256: verified.Digest, TransitionID: verified.Request.TransitionID, SourceNodeID: cfg.NodeID, ControlEpoch: verified.Request.ControlEpoch, CreatedAt: time.Now().UTC(), Objects: objects}
	receiptRaw, err := preliminarycapture.SignReceipt(signer, receipt)
	if err != nil {
		return err
	}
	if _, err := preliminarycapture.VerifyReceipt(publicPEM, receiptRaw); err != nil {
		return err
	}
	if err := captureAuthority(global, verified.Request.ControlEpoch); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.PublishReceipt(ctx, receiptRaw); err != nil {
		return err
	}
	return w.completeCapture(ctx, global, verified.Request.ControlEpoch, status, receiptRaw)
}

func (w *preliminaryWorker) completeCapture(ctx context.Context, global func() authority.RegionalAuthoritySnapshot, epoch uint64, status PreliminaryCaptureStatus, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := captureAuthority(global, epoch); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	status.State, status.Error = "complete", ""
	status.ReceiptSHA256 = hex.EncodeToString(digest[:])
	status.CapturedStreams = status.TotalStreams
	w.setStatus(status)
	return nil
}

func captureAccount(ctx context.Context, nc *nats.Conn, store restoredrill.SnapshotObjectStore, account preliminarycapture.AccountInventory, verified preliminarycapture.VerifiedRequest, maximum int64, progress func()) ([]preliminarycapture.Object, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}
	checkInventory := func() error {
		inventoryCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		list := js.StreamNames(inventoryCtx)
		var observed []string
		for name := range list.Name() {
			observed = append(observed, name)
			if len(observed) > len(account.Streams) {
				return errors.New("initial control: unexpected source stream")
			}
		}
		if list.Err() != nil || !equalStrings(observed, account.Streams) {
			return errors.New("initial control: source account inventory differs")
		}
		return nil
	}
	if err := checkInventory(); err != nil {
		return nil, err
	}
	var objects []preliminarycapture.Object
	for _, stream := range account.Streams {
		key, err := preliminarycapture.ObjectKey(account.Account, stream, verified.Request.ControlEpoch)
		if err != nil {
			return nil, err
		}
		snapshotter, err := restoredrill.NewNATSJetStreamSnapshotter(restoredrill.NATSJetStreamSnapshotterConfig{Connection: nc, Stream: stream, Store: store, Region: "gru", Bucket: account.Account, MaxBytes: maximum})
		if err != nil {
			return nil, err
		}
		snapshot, err := snapshotter.Snapshot(ctx, restoredrill.SnapshotRequest{RunID: verified.Request.TransitionID, IdempotencyKey: verified.Request.TransitionID, ObjectKey: key, ControlEpoch: verified.Request.ControlEpoch})
		if err != nil {
			return nil, fmt.Errorf("capture %s/%s: %w", account.Account, stream, err)
		}
		objects = append(objects, preliminarycapture.Object{Account: account.Account, Stream: stream, Key: key, SHA256: snapshot.Checksum, Size: snapshot.Size, CreatedAt: snapshot.CreatedAt})
		progress()
	}
	return objects, checkInventory()
}
