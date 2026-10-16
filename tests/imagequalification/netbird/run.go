// Package netbird exercises the dedicated NetBird role on confined disposable images.
// It produces observations for the existing qualifier; it is not a signing authority.
package netbird

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/native"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird/protocol"
)

type Artifact struct {
	protocol.Artifact
	ArchivePath string
}

// Removal must come from the parent's confined OCI terminate-and-wait operation.
// Stopping a process is insufficient to establish original-host removal.
type Removal struct {
	InstanceID string    `json:"instance_id"`
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observed_at"`
}

type Request struct {
	RunID          string
	Candidate      release.ProductionExpectation
	ImageOCID      string
	Hosts          [2]native.Host // Primary, then the independently isolated replacement.
	PrivateKeyPath string
	WorkerPath     string
	WorkerSHA256   string
	ContainerdPath string
	RuncPath       string
	Artifacts      []Artifact
	ClientPath     string
	ClientSHA256   string
	RemovePrimary  func(context.Context, string) (Removal, error)
}

var runIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Run requires already authenticated finite approval and effective confinement.
// The parent separately verifies every artifact pin against that signed approval.
func Run(ctx context.Context, req Request) (native.Report, error) {
	report := native.Report{RunID: req.RunID, Candidate: req.Candidate, ImageOCID: req.ImageOCID, StartedAt: time.Now().UTC()}
	if err := validate(req); err != nil {
		return report, err
	}
	for _, artifact := range req.Artifacts {
		if err := verifyFile(artifact.ArchivePath, artifact.ArchiveSHA256); err != nil {
			return report, fmt.Errorf("%s archive: %w", artifact.Role, err)
		}
	}
	if err := verifyFile(req.ClientPath, req.ClientSHA256); err != nil {
		return report, fmt.Errorf("NetBird client: %w", err)
	}
	var sessions [2]exchange
	for i, host := range req.Hosts {
		session, err := native.OpenSession(ctx, native.SessionConfig{RunID: req.RunID, Host: host, User: "root", PrivateKeyPath: req.PrivateKeyPath, WorkerPath: req.WorkerPath, WorkerSHA256: req.WorkerSHA256})
		if err != nil {
			for _, opened := range sessions {
				if opened != nil {
					_ = opened.Close()
				}
			}
			return report, fmt.Errorf("open NetBird host %d: %w", i, err)
		}
		sessions[i] = session
		for _, artifact := range req.Artifacts {
			if err := session.UploadFile(ctx, artifact.Role+".oci", artifact.ArchivePath, artifact.ArchiveSHA256); err != nil {
				for _, opened := range sessions {
					if opened != nil {
						_ = opened.Close()
					}
				}
				return report, err
			}
		}
		if err := session.UploadFile(ctx, "client", req.ClientPath, req.ClientSHA256); err != nil {
			for _, opened := range sessions {
				if opened != nil {
					_ = opened.Close()
				}
			}
			return report, err
		}
	}
	return run(ctx, req, report, sessions)
}

type exchange interface {
	Exchange(context.Context, any, any) error
	Close() error
}

func validate(req Request) error {
	c := req.Candidate
	if !runIDPattern.MatchString(req.RunID) || !release.ValidSourceRevision(c.SourceRevision) ||
		c.Role != "netbird-manager" || c.Runtime != "netbird-containerd" || c.Cell != "GRU" || c.Architecture != "arm64" ||
		!release.ValidEnvironment(c.Environment) || !hashPattern.MatchString(c.ArtifactSHA256) || !hashPattern.MatchString(c.QualificationSHA256) ||
		!strings.HasPrefix(req.ImageOCID, "ocid1.image.") || !hashPattern.MatchString(req.WorkerSHA256) ||
		!hashPattern.MatchString(req.ClientSHA256) || req.RemovePrimary == nil {
		return errors.New("incomplete dedicated NetBird candidate, artifacts or confined removal")
	}
	for i, host := range req.Hosts {
		address, err := netip.ParseAddr(host.Address)
		if err != nil || !address.Is4() || !address.IsPrivate() || !strings.HasPrefix(host.OCID, "ocid1.instance.") || host.SSHHostKey == "" ||
			host.ExpectedIdentity.ImageOCID != req.ImageOCID || host.ExpectedIdentity.InstanceID != host.OCID || host.ExpectedIdentity.Architecture != c.Architecture || host.ExpectedIdentity.KernelRelease == "" {
			return errors.New("NetBird hosts require pinned distinct private native Compute identities")
		}
		if i == 1 && (host.OCID == req.Hosts[0].OCID || host.Address == req.Hosts[0].Address) {
			return errors.New("NetBird replacement must use a different host")
		}
		for _, hash := range []string{host.ExpectedIdentity.KernelSHA256, host.ExpectedIdentity.BinarySHA256, host.ExpectedIdentity.ContainerdSHA256, host.ExpectedIdentity.RuncSHA256} {
			if !hashPattern.MatchString(hash) {
				return errors.New("missing exact native component hash")
			}
		}
	}
	roles := map[string]bool{}
	for _, artifact := range req.Artifacts {
		_, imageHash, found := strings.Cut(artifact.Image, "@sha256:")
		if !slices.Contains([]string{"server", "dashboard", "ingress"}, artifact.Role) || roles[artifact.Role] || !found || !hashPattern.MatchString(imageHash) || !hashPattern.MatchString(artifact.ArchiveSHA256) {
			return errors.New("NetBird requires exactly pinned server, dashboard and ingress archives")
		}
		roles[artifact.Role] = true
	}
	if len(roles) != 3 {
		return errors.New("NetBird requires all three upstream component archives")
	}
	return nil
}

func verifyFile(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("artifact must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != expected {
		return errors.New("artifact digest differs")
	}
	return nil
}

func run(ctx context.Context, req Request, initial native.Report, sessions [2]exchange) (report native.Report, runErr error) {
	report = initial
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var events []jsontext.Value
	started := time.Now().UTC()
	primaryRemoved := false
	call := func(ctx context.Context, host int, operation string, private []byte) (protocol.Response, error) {
		command := protocol.Command{Operation: operation, RunID: req.RunID, SourceRevision: req.Candidate.SourceRevision, Host: req.Hosts[host], ContainerdPath: req.ContainerdPath, RuncPath: req.RuncPath, ClientSHA256: req.ClientSHA256, Private: private}
		for _, artifact := range req.Artifacts {
			command.Artifacts = append(command.Artifacts, artifact.Artifact)
		}
		var response protocol.Response
		err := sessions[host].Exchange(ctx, command, &response)
		// Credentials and upstream error bodies never enter retained transcripts.
		wire, _ := json.Marshal(struct {
			Host        string               `json:"host"`
			Operation   string               `json:"operation"`
			Observation protocol.Observation `json:"observation"`
		}{Host: req.Hosts[host].OCID, Operation: operation, Observation: response.Observation}, json.Deterministic(true))
		events = append(events, wire)
		if err != nil || response.Error != "" {
			return response, fmt.Errorf("NetBird %s failed on host %d", operation, host)
		}
		return response, nil
	}
	finish := func(name, gate string) {
		wire, _ := json.Marshal(events, json.Deterministic(true))
		report.Scenarios = append(report.Scenarios, native.Scenario{Name: name, Gate: gate, StartedAt: started, CompletedAt: time.Now().UTC(), HostIDs: []string{req.Hosts[0].OCID, req.Hosts[1].OCID}, Transcript: wire, TranscriptSHA256: fmt.Sprintf("%x", sha256.Sum256(wire))})
		events = nil
		started = time.Now().UTC()
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		for i, session := range sessions {
			if i != 0 || !primaryRemoved {
				_, err := call(cleanup, i, "cleanup", nil)
				runErr = errors.Join(runErr, err)
			}
			_ = session.Close()
		}
		finish("cleanup", "")
		if runErr == nil {
			report.CompletedAt = time.Now().UTC()
		}
	}()
	for i := range req.Hosts {
		response, err := call(ctx, i, "identity", nil)
		if err != nil {
			return report, err
		}
		observed := response.Observation
		if observed.Identity != req.Hosts[i].ExpectedIdentity || observed.WorkerSHA256 != req.WorkerSHA256 || observed.WorkerSourceRevision != req.Candidate.SourceRevision {
			return report, errors.New("NetBird host or worker differs from exact candidate")
		}
		report.Hosts = append(report.Hosts, native.HostReport{Role: []string{"netbird-primary", "netbird-replacement"}[i], OCID: req.Hosts[i].OCID, Address: req.Hosts[i].Address, Observed: observed.Identity, WorkerSHA256: observed.WorkerSHA256, WorkerSourceRevision: observed.WorkerSourceRevision})
	}
	store, err := call(ctx, 1, "backup-store", nil)
	if err != nil {
		return report, err
	}
	defer clear(store.Private)
	initial, err := call(ctx, 0, "foundation", nil)
	if err != nil {
		return report, err
	}
	if err := validateFoundation(initial.Observation, req); err != nil {
		return report, err
	}
	restarted, err := call(ctx, 0, "restart", nil)
	if err != nil || !sameAccount(initial.Observation.Account, restarted.Observation.Account) {
		return report, errors.New("NetBird restart lost account or peer continuity")
	}
	rotated, err := call(ctx, 0, "rotate", nil)
	if err != nil || !sameIdentity(initial.Observation.Account, rotated.Observation.Account) || rotated.Observation.Account.ServiceTokenID == initial.Observation.Account.ServiceTokenID ||
		rotated.Observation.CredentialVersion == "" || rotated.Observation.DeniedHTTPStatus != 401 || rotated.Observation.Account.ServiceHTTPStatus != 200 {
		return report, errors.New("NetBird credential rotation did not preserve identity and reject the previous credential")
	}
	finish("netbird-foundation", "netbird-foundation")
	backup, err := call(ctx, 0, "backup", store.Private)
	if err != nil || backup.Observation.BackupObject == "" || !hashPattern.MatchString(backup.Observation.BackupSHA256) || backup.Observation.BackupBytes <= 0 ||
		backup.Observation.BackupStorage != "signed-sdk-fixture" || len(backup.Observation.BackupCopies) != 2 {
		return report, errors.New("NetBird protected backup fixture was not observed")
	}
	for i, copy := range backup.Observation.BackupCopies {
		if copy.Region != []string{"sa-saopaulo-1", "us-sanjose-1"}[i] || copy.SHA256 != backup.Observation.BackupSHA256 || copy.Bytes != backup.Observation.BackupBytes {
			return report, errors.New("NetBird backup fixture download differs from the archive")
		}
	}
	defer clear(backup.Private)
	if _, err = call(ctx, 0, "retire", nil); err != nil {
		return report, err
	}
	removed, err := req.RemovePrimary(ctx, req.Hosts[0].OCID)
	if err != nil || removed.InstanceID != req.Hosts[0].OCID || removed.State != "TERMINATED" || removed.ObservedAt.Before(started) || removed.ObservedAt.After(time.Now().UTC()) {
		return report, errors.New("original NetBird Compute host removal was not authenticated")
	}
	primaryRemoved = true
	wire, _ := json.Marshal(removed, json.Deterministic(true))
	events = append(events, wire)
	restored, err := call(ctx, 1, "restore", backup.Private)
	if err != nil || restored.Observation.RestoredSHA256 != backup.Observation.BackupSHA256 || !sameAccount(rotated.Observation.Account, restored.Observation.Account) {
		return report, errors.New("replacement NetBird account, peer or access continuity differs from protected backup")
	}
	if err := validateFoundation(restored.Observation, req); err != nil {
		return report, err
	}
	// The SDK fixture exercises restore; it cannot establish real provider retention or regional durability.
	finish("netbird-recovery", "")
	return report, nil
}

func validateFoundation(observation protocol.Observation, req Request) error {
	a := observation.Account
	if a.AccountID == "" || a.OwnerID == "" || a.ServiceID == "" || a.ServiceID == a.OwnerID || a.ServiceTokenID == "" || a.PeerID == "" ||
		!hashPattern.MatchString(a.PeerKeySHA256) || !hashPattern.MatchString(a.PolicySHA256) || a.PeerAddress == "" || a.StoreID == "" || len(a.PolicyIDs) == 0 || len(a.UnrestrictedPolicyIDs) != 0 || a.SetupHTTPStatus != 403 || a.ServiceHTTPStatus != 200 || a.PeerHTTPStatus != 200 ||
		observation.TLSProtocol != "TLSv1.3" || observation.TLSAuthority != "fixture-internal" || observation.GRPCStatus != "0" || observation.STUNTransaction == "" || len(observation.Components) != 3 {
		return errors.New("NetBird foundation lacks actual closed setup, service, enrolled peer, policy or protocol observations")
	}
	for _, artifact := range req.Artifacts {
		found := false
		for _, component := range observation.Components {
			if component.Name == "netbird-"+artifact.Role {
				found = component.Image == artifact.Image && component.PID > 0 && component.Containers == 1
			}
		}
		if !found {
			return errors.New("NetBird native runtime component does not match pinned archive")
		}
	}
	return nil
}

func sameIdentity(a, b protocol.Account) bool {
	return a.AccountID == b.AccountID && a.OwnerID == b.OwnerID && a.ServiceID == b.ServiceID && a.PeerID == b.PeerID && a.PeerKeySHA256 == b.PeerKeySHA256 && a.PeerAddress == b.PeerAddress && a.StoreID == b.StoreID && a.PolicySHA256 == b.PolicySHA256 && slices.Equal(a.PolicyIDs, b.PolicyIDs)
}

func sameAccount(a, b protocol.Account) bool {
	return sameIdentity(a, b) && a.ServiceTokenID == b.ServiceTokenID && b.ServiceHTTPStatus == 200 && b.PeerHTTPStatus == 200 && b.SetupHTTPStatus == 403
}
