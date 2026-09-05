package initialcontrol

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/restoresnapshot"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/sourcepublication"
)

// PreliminaryPublicationStatus describes source publication of captured bytes.
// Completion supplies no candidate restore or promotion evidence.
type PreliminaryPublicationStatus struct {
	State         string `json:"state"`
	RequestSHA256 string `json:"requestSha256,omitempty"`
	ScopeSHA256   string `json:"scopeSha256,omitempty"`
	TransitionID  string `json:"transitionId,omitempty"`
	ReceiptSHA256 string `json:"receiptSha256,omitempty"`
	Error         string `json:"error,omitempty"`
}

type preliminaryPublicationWorker struct {
	done   chan struct{}
	mu     sync.Mutex
	status PreliminaryPublicationStatus
}

func (r *Runtime) PreliminaryPublication() PreliminaryPublicationStatus {
	if r == nil || r.publication == nil {
		return PreliminaryPublicationStatus{State: "disabled"}
	}
	return r.publication.snapshot()
}
func (w *preliminaryPublicationWorker) snapshot() PreliminaryPublicationStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}
func (w *preliminaryPublicationWorker) setStatus(status PreliminaryPublicationStatus) {
	w.mu.Lock()
	w.status = status
	w.mu.Unlock()
}

func startPreliminaryPublicationWorker(ctx context.Context, admission *initialgrant.Admission, global func() authority.RegionalAuthoritySnapshot) *preliminaryPublicationWorker {
	w := &preliminaryPublicationWorker{done: make(chan struct{}), status: PreliminaryPublicationStatus{State: "idle"}}
	go w.run(ctx, time.Second,
		func() ([]byte, error) {
			return initialgrant.ReadPreliminaryUpload(admission.Config().PreliminaryCapture.Publication.RequestFile)
		},
		func(raw []byte) error { _, err := publicationAuthority(ctx, admission, global, raw); return err },
		func(raw []byte) error { return w.publish(ctx, admission, global, raw) })
	return w
}

// Each verified request gets at most three attempts in this runtime. A fresh
// signed authorization starts a new budget; missing ingress does not reset it.
func (w *preliminaryPublicationWorker) run(ctx context.Context, interval time.Duration, read func() ([]byte, error), authorize func([]byte) error, publish func([]byte) error) {
	defer close(w.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var completed []byte
	var completeStatus PreliminaryPublicationStatus
	var attempted string
	var attempts int
	for {
		if ctx.Err() != nil {
			return
		}
		raw, err := read()
		if err == nil {
			err = authorize(raw)
		}
		if err == nil {
			if bytes.Equal(raw, completed) {
				w.setStatus(completeStatus)
			} else {
				digest := preliminarytransfer.Digest(raw)
				if digest != attempted {
					attempted, attempts = digest, 0
				}
				if attempts >= 3 {
					err = errors.New("initial control: publication retry budget exhausted")
				} else {
					attempts++
					err = publish(raw)
					if err == nil {
						completed = append([]byte(nil), raw...)
						completeStatus = w.snapshot()
					}
				}
			}
		}
		if errors.Is(err, os.ErrNotExist) {
			w.setStatus(PreliminaryPublicationStatus{State: "idle"})
		} else if err != nil && ctx.Err() == nil {
			status := w.snapshot()
			status.State = "failed"
			status.Error = "preliminary publication refused or incomplete"
			w.setStatus(status)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func publicationAuthority(ctx context.Context, admission *initialgrant.Admission, global func() authority.RegionalAuthoritySnapshot, raw []byte) (preliminarytransfer.VerifiedUpload, error) {
	upload, err := admission.VerifyPreliminaryUpload(ctx, raw)
	if err != nil {
		return preliminarytransfer.VerifiedUpload{}, err
	}
	if global == nil {
		return preliminarytransfer.VerifiedUpload{}, errors.New("initial control: live global publication authority required")
	}
	if err := captureAuthority(global, upload.Authorization.ControlEpoch); err != nil {
		return preliminarytransfer.VerifiedUpload{}, err
	}
	if err := publicationRequestUnchanged(ctx, admission.Config().PreliminaryCapture.Publication.RequestFile, raw); err != nil {
		return preliminarytransfer.VerifiedUpload{}, err
	}
	return upload, nil
}

func publicationRequestUnchanged(ctx context.Context, path string, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := initialgrant.ReadPreliminaryUpload(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, raw) {
		return errors.New("initial control: publication request changed")
	}
	return ctx.Err()
}

func (w *preliminaryPublicationWorker) publish(ctx context.Context, admission *initialgrant.Admission, global func() authority.RegionalAuthoritySnapshot, raw []byte) error {
	upload, err := publicationAuthority(ctx, admission, global, raw)
	if err != nil {
		return err
	}
	cfg := admission.Config()
	profiles, err := buildProfiles(cfg.Cell, cfg.SeedInstance)
	if err != nil {
		return err
	}
	historical, err := upload.Scope.HistoricalCapture()
	if err != nil {
		return err
	}
	if len(historical.Request.Accounts) != 2 || !equalStrings(historical.Request.Accounts[0].Streams, captureStreamNames(profiles.Regional)) || !equalStrings(historical.Request.Accounts[1].Streams, captureStreamNames(profiles.Global)) {
		return errors.New("initial control: publication inventory differs from complete initial profile")
	}
	status := PreliminaryPublicationStatus{State: "publishing", RequestSHA256: upload.Digest, ScopeSHA256: upload.Scope.Digest, TransitionID: upload.Scope.Scope.TransitionID}
	w.setStatus(status)
	operation, cancel := context.WithDeadline(ctx, upload.Authorization.ExpiresAt)
	defer cancel()
	bounded, stop := context.WithTimeout(operation, 10*time.Minute)
	defer stop()
	guard := func(check context.Context) error {
		_, err := publicationAuthority(check, admission, global, raw)
		return err
	}
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
				if guard(bounded) != nil {
					stop()
					return
				}
			}
		}
	}()
	defer func() { stop(); <-monitorDone }()
	return admission.WithinMutation(bounded, func(op context.Context) error {
		receipt, err := publishPreliminaryAdmitted(op, cfg, upload, profiles, guard)
		if err != nil {
			return err
		}
		if err := guard(op); err != nil {
			return err
		}
		status.State = "complete"
		status.ReceiptSHA256 = preliminarytransfer.Digest(receipt)
		w.setStatus(status)
		return nil
	})
}

func publishPreliminaryAdmitted(ctx context.Context, cfg initialgrant.Config, upload preliminarytransfer.VerifiedUpload, profiles profiles, guard func(context.Context) error) ([]byte, error) {
	if err := guard(ctx); err != nil {
		return nil, err
	}
	key, err := readCredential(cfg.Membership.SigningKeyFile, "", true)
	if err != nil {
		return nil, err
	}
	signer, err := security.ParseCommandSignatureSignerPEM(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	sourceID, err := preliminarytransfer.PublicKeyID([]byte(upload.Scope.Scope.SourcePublicKeyPEM))
	if err != nil || signer.PublicKeyID() != sourceID {
		return nil, errors.New("initial control: publication signer differs from admitted capture source")
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	settings := cfg.PreliminaryCapture.Publication
	connection, err := connect(ctx, cfg.Broker, settings.Journal)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := guard(ctx); err != nil {
		return nil, err
	}
	js, err := jetstream.New(connection)
	if err != nil {
		return nil, err
	}
	var journalProfile accountProfile
	for _, kv := range profiles.Regional.KV {
		if kv.Bucket == "ORCH_OPERATIONS" {
			journalProfile.KV = append(journalProfile.KV, kv)
		}
	}
	if len(journalProfile.KV) != 1 {
		return nil, errors.New("initial control: exact publication journal profile required")
	}
	if err := readback(ctx, js, journalProfile, false); err != nil {
		return nil, err
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	kv, err := js.KeyValue(ctx, "ORCH_OPERATIONS")
	if err != nil {
		return nil, err
	}
	journal, err := provider.NewNatsOwnershipCASStore(kv)
	if err != nil {
		return nil, err
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	identity, err := ociinstance.NewFromConfig(ctx, settings.Identity, func(path string) ([]byte, error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return readCredential(path, "", true)
	})
	if err != nil {
		return nil, err
	}
	defer identity.Close()
	regions := make(map[string]restoresnapshot.Region, len(upload.Scope.Scope.Destinations))
	for _, destination := range upload.Scope.Scope.Destinations {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		transport, err := identity.NewTransportForRegion(provider.OCIServiceObjectStorage, destination.OCIRegion, max(upload.Scope.Scope.MaxSnapshotBytes, preliminarytransfer.MaximumBytes))
		if err != nil {
			return nil, err
		}
		regions[destination.Region] = restoresnapshot.Region{Transport: transport, OCIRegion: destination.OCIRegion, Namespace: destination.Namespace, Bucket: destination.Bucket, BucketResourceID: destination.BucketResourceID, CompartmentID: destination.CompartmentID, OwnershipGeneration: destination.OwnershipGeneration}
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	return sourcepublication.Publish(ctx, sourcepublication.Config{Upload: upload, OutputDir: cfg.PreliminaryCapture.OutputDir, StateDir: settings.StateDir, Journal: journal, Regions: regions, Signer: signer, Guard: guard})
}
