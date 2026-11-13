package releasepush

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/datamount"
	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
	"github.com/nats-io/nats.go"
)

const (
	SubjectVersion = protocol.ReleaseVersion
	SubjectHealth  = protocol.ReleaseHealth
	SubjectOrch    = protocol.ReleaseOrch
	SubjectApp     = protocol.ReleaseApp
	SubjectPing    = protocol.ReleaseMeshPing
	SubjectApply   = protocol.ReleaseMeshApply
	SubjectRemove  = protocol.ReleaseMeshRemove
	SubjectState   = protocol.ReleaseMeshState

	orchRepository = owner + "/ts-orchestrator"
	downloadPrefix = "https://github.com/" + orchRepository + "/releases/download/"
	assetPrefix    = "terrascale-orchestrator-linux-"
	maxBinaryBytes = 512 << 20
)

const (
	HandlerWait          = 25 * time.Minute
	healthHandlerBudget  = 5 * time.Second
	healthRequestTimeout = 8 * time.Second
)

var (
	hex40    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	appImage = regexp.MustCompile(`^ghcr\.io/terrascale/([a-z0-9][a-z0-9._-]{0,127})@sha256:[0-9a-f]{64}$`)
)

type Binary struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type OrchRelease struct {
	SHA      string            `json:"sha"`
	Binaries map[string]Binary `json:"binaries"`
	Token    string            `json:"token"`
}

type AppRelease struct {
	Service string `json:"service"`
	Image   string `json:"image"`
	Token   string `json:"token"`
}

type MeshRequest struct {
	Token string          `json:"token"`
	Spec  json.RawMessage `json:"spec,omitempty"`
}

type Reply struct {
	DataMount      *datamount.Report `json:"data_mount,omitempty"`
	DataMountError string            `json:"data_mount_error,omitempty"`

	State   string `json:"state,omitempty"` // current, installed, stale, rolled_back, rejected; done, failed for mesh
	Version string `json:"version,omitempty"`
	Health  string `json:"health,omitempty"`
	Error   string `json:"error,omitempty"`
	// RolledBack is the release this host restored <binary>.prev over; Error says why.
	RolledBack string `json:"rolled_back,omitempty"`
	// Result is the mesh's per-region rows.
	Result   json.RawMessage `json:"result,omitempty"`
	Deadline time.Time       `json:"deadline,omitzero"`
	Refusal  *Refusal        `json:"refusal,omitempty"`
	Events   []string        `json:"events,omitempty"`
	NodeList nodelist.Status `json:"node_list,omitzero"`
	Host     string          `json:"host,omitempty"`
	Workers  []HostVersion   `json:"workers,omitempty"`
}

type HealthRequest struct {
	Service string `json:"service"`
}

type HealthResult struct {
	Mesh    error
	Service error
}

func (result HealthResult) Err() error {
	return errors.Join(result.Mesh, result.Service)
}

type Progress interface {
	Deadline(time.Time)
	Event(string)
}

type Handler struct {
	probation *Probation
	NodeList  *nodelist.Store
	Health    func(context.Context, string) HealthResult
	Verifier  *Verifier
	// Revision is the running build's vcs.revision.
	Revision string
	// Binary is the installed executable that a release replaces.
	Binary        string
	runningBinary string
	// RunIDFile records the installed release's GitHub run_id; an older run is refused.
	RunIDFile string
	// TrialFile is the probation marker install writes (Probe); RollbackFile
	// records the last release that never served.
	TrialFile, RollbackFile string
	Client                  *http.Client
	App                     func(ctx context.Context, service, image string, claims Claims, progress Progress) (json.RawMessage, error)
	Mesh                    func(ctx context.Context, op string, spec json.RawMessage) (json.RawMessage, error)
	Relay                   func(context.Context, []byte) []HostVersion
	Installed               chan struct{}

	RefusalFile   string
	mu            sync.Mutex
	pending       string
	exitOnce      sync.Once
	lastHealth    atomic.Pointer[string]
	appOperations map[appOperationKey]*appOperation
}

func NewHandler(state string) (*Handler, error) {
	binary, err := executable()
	if err != nil {
		return nil, err
	}
	h := &Handler{Verifier: NewVerifier(), Revision: Revision(), Binary: binary, runningBinary: binary,
		RunIDFile: filepath.Join(state, "nats", "release-run-id"), TrialFile: trialFile(state), RollbackFile: rollbackFile(state),
		Client: &http.Client{}, Installed: make(chan struct{}, 1)}
	probation, err := Probe(state, os.Stderr)
	if err != nil {
		return nil, err
	}
	h.probation = probation
	h.NodeList = nodelist.Open(state)
	h.RefusalFile = filepath.Join(state, "nats", "release-attempt.json")
	return h, nil
}

func executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func Revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return buildRevision(info)
}

func (h *Handler) Serve(conn *nats.Conn) error {
	return h.serve(conn, map[string]func(context.Context, []byte) Reply{
		SubjectVersion: func(context.Context, []byte) Reply { return h.version() },
		SubjectHealth:  h.health,
		SubjectOrch:    h.relayed,
		SubjectApp:     h.app,
		SubjectPing:    func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "ping", data) },
		SubjectApply:   func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "apply", data) },
		SubjectRemove:  func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "rm", data) },
		SubjectState:   func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "state", data) },
	})
}

func (h *Handler) ServeWorker(conn *nats.Conn, subject, host string) error {
	return h.serve(conn, map[string]func(context.Context, []byte) Reply{subject: func(ctx context.Context, data []byte) Reply {
		reply := h.orch(ctx, data)
		reply.Host = host
		return reply
	}})
}

func (h *Handler) relayed(ctx context.Context, data []byte) Reply {
	reply := h.orch(ctx, data)
	host, _ := os.Hostname()
	reply.Host = secretpreflight.Scrub(host)
	if h.Relay != nil && (reply.State == "installed" || reply.State == "current" || reply.Refusal != nil && reply.Refusal.Preflight) {
		relayCtx, cancel := context.WithTimeout(ctx, WorkerReplyWait)
		defer cancel()
		completed := make(chan []HostVersion, 1)
		go func() { completed <- h.Relay(relayCtx, data) }()
		select {
		case reply.Workers = <-completed:
			for _, worker := range reply.Workers {
				if worker.Error != "" {
					slog.Warn("release worker relay incomplete", "error", worker.Error)
				}
			}
		case <-relayCtx.Done():
			slog.Warn("release worker relay incomplete", "error", relayCtx.Err())
		}
	}
	return reply
}

func (h *Handler) serve(conn *nats.Conn, subjects map[string]func(context.Context, []byte) Reply) error {
	for subject, handle := range subjects {
		if _, err := conn.Subscribe(subject, func(m *nats.Msg) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), HandlerWait)
				defer cancel()
				reply := handle(ctx, m.Data)
				if reply.Error != "" {
					slog.Warn("release request failed", "subject", subject, "state", reply.State, "error", reply.Error)
				}
				data, _ := json.Marshal(reply)
				if err := m.Respond(data); err != nil {
					slog.Warn("release reply delivery failed", "error", err)
				}
				if reply.State == "installed" {
					if err := conn.FlushTimeout(5 * time.Second); err != nil {
						slog.Warn("release installed; reply flush failed", "error", err)
					}
					h.startProbation()
					h.exitAfter(time.Second)
					select {
					case h.Installed <- struct{}{}:
					default:
						slog.Warn("release restart notification not delivered")
					}
				}

			}()
		}); err != nil {
			return err
		}
	}
	return conn.Flush()
}

func rejected(err error) Reply { return Reply{State: "rejected", Error: err.Error()} }

func (h *Handler) version() Reply {
	reply := Reply{Version: h.Revision, NodeList: h.NodeList.Status()}
	id, err := binaryIdentity(h.Binary)
	if err != nil {
		reply.State, reply.Error = "unconfirmed", "installed binary identity unavailable"
		return reply
	}
	if record, ok := h.activeTrialID(id); ok {
		reply.State = "probation"
		if record.Failure != "" {
			reply.State, reply.Error = "unconfirmed", record.Failure
		}
	}
	if record, ok := selected[Rollback](h.RollbackFile, id); ok && record.Rejected.SHA != "" {
		reply.RolledBack, reply.Error = record.Rejected.SHA, record.Reason
	}
	reply.Refusal = h.refusal(id)
	return reply
}

func (h *Handler) health(ctx context.Context, data []byte) Reply {
	var request HealthRequest
	if len(data) != 0 {
		if err := protocol.DecodeStrict(data, &request, 64<<10); err != nil {
			return Reply{Version: h.Revision, Health: err.Error()}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, healthHandlerBudget)
	defer cancel()
	text := "no health check"
	if !h.mu.TryLock() {
		return Reply{Version: h.Revision, Health: "release install in progress"}
	}
	pending := h.pending
	h.mu.Unlock()
	if pending != "" {
		return Reply{Version: h.Revision, Health: "release restart pending"}
	}
	if record, ok := h.activeTrial(); ok {
		return Reply{Version: h.Revision, State: "unconfirmed", Health: "release probation unconfirmed: " + record.Failure}
	}
	if h.Health != nil {
		text = "ok"
		if err := h.Health(ctx, request.Service).Err(); err != nil {
			text = err.Error()
		}
	}
	if previous := h.lastHealth.Swap(&text); previous == nil || *previous != text {
		slog.Info("release health changed", "health", text)
	}
	mount, err := datamount.Read(ctx)
	mountError := ""
	if err != nil {
		mountError = err.Error()
	}
	return Reply{Version: h.Revision, Health: text, DataMount: mount, DataMountError: mountError}
}

func (h *Handler) orch(ctx context.Context, data []byte) (reply Reply) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var release OrchRelease
	if err := protocol.DecodeStrict(data, &release, 64<<10); err != nil {
		return integrityReply(release.SHA, Claims{}, err)
	}
	binary, claims, err := h.validateOrch(ctx, release)
	if err != nil {
		var host *hostError
		if errors.As(err, &host) {
			return refusalReply(RefusalHost, release.SHA, binary.SHA256, claims, err)
		}
		return integrityReply(release.SHA, claims, err)
	}
	if release.SHA == h.pending {
		return Reply{State: "installed", Version: release.SHA}
	}
	if release.SHA == h.Revision {
		return Reply{State: "current", Version: h.Revision}
	}
	if id, err := binaryIdentity(h.Binary); err == nil {
		if record, ok := selected[Rollback](h.RollbackFile, id); ok && record.Rejected.SHA == release.SHA && record.RunID == claims.RunID {
			return Reply{State: "rolled_back", Version: h.Revision, RolledBack: record.Rejected.SHA, Error: record.Reason}
		}
	}
	if stale, err := h.olderRun(claims.RunID); err != nil {
		return refusalReply(RefusalHost, release.SHA, binary.SHA256, claims, err)
	} else if stale {
		return Reply{State: "stale", Error: "an equal or newer run is installed"}
	}
	if err := h.install(ctx, binary, release.SHA, claims); err != nil {
		kind := RefusalHost
		var integrity *integrityError
		if errors.As(err, &integrity) {
			kind = RefusalIntegrity
		}
		reply = refusalReply(kind, release.SHA, binary.SHA256, claims, err)
		var preflight *preflightError
		reply.Refusal.Preflight = errors.As(err, &preflight)
		attempt := *reply.Refusal
		if err := h.recordAttempt(&attempt); err != nil {
			slog.Warn("release refusal diagnostic not saved", "error", err)
		}
		return reply
	}
	h.pending = release.SHA
	attempt := &Refusal{Kind: RefusalHost, SHA: release.SHA, SHA256: binary.SHA256, RunID: claims.RunID, RunAttempt: claims.RunAttempt}
	if err := h.recordAttempt(attempt); err != nil {
		slog.Warn("release installed; diagnostic attempt record not saved", "error", err)
	}
	return Reply{State: "installed", Version: release.SHA}
}

func (h *Handler) activeTrial() (trial, bool) {
	id, err := binaryIdentity(h.Binary)
	if err != nil {
		return trial{}, false
	}
	return h.activeTrialID(id)
}

func (h *Handler) activeTrialID(id releaseID) (trial, bool) {
	if id.SHA != h.Revision {
		return trial{}, false
	}
	if h.probation != nil {
		h.probation.mu.Lock()
		defer h.probation.mu.Unlock()
		if !h.probation.served && h.probation.trial.identity() == id {
			return h.probation.trial, true
		}
	}
	return selected[trial](h.TrialFile, id)
}

func (h *Handler) startProbation() {
	h.mu.Lock()
	defer h.mu.Unlock()
	id, err := binaryIdentity(h.Binary)
	if err != nil {
		slog.Warn("release activation request unavailable", "error", err)
		return
	}
	record, ok := selected[trial](h.TrialFile, id)
	if !ok || !record.Requested.IsZero() {
		return
	}
	record.Requested = time.Now()
	if err := storeRecord(h.TrialFile, record, id); err != nil {
		slog.Warn("release installed; activation request not saved", "error", err)
	}
}

func ReleaseTag(sha, runID string) string { return "ci-" + sha + "-run-" + runID }

func ReleaseURL(sha, runID, arch string) string {
	return downloadPrefix + ReleaseTag(sha, runID) + "/" + assetPrefix + arch
}

func (h *Handler) validateOrch(ctx context.Context, release OrchRelease) (Binary, Claims, error) {
	if !hex40.MatchString(release.SHA) {
		return Binary{}, Claims{}, errors.New("sha must be 40 lowercase hex")
	}
	binary, ok := release.Binaries[runtime.GOARCH]
	if !ok {
		return Binary{}, Claims{}, errors.New("no binary for " + runtime.GOARCH)
	}
	if !hex64.MatchString(binary.SHA256) {
		return Binary{}, Claims{}, errors.New("sha256 must be 64 lowercase hex")
	}
	claims, err := h.Verifier.Verify(ctx, release.Token)
	if err != nil {
		return binary, Claims{}, err
	}
	if claims.JobWorkflowRef != orchWorkflow || claims.SHA != release.SHA {
		return Binary{}, Claims{}, errors.New("token is not for this ts-orchestrator commit")
	}
	if want := ReleaseURL(release.SHA, claims.RunID, runtime.GOARCH); binary.URL != want {
		return Binary{}, Claims{}, errors.New("url must be " + want)
	}
	return binary, claims, nil
}

func (h *Handler) olderRun(runID string) (bool, error) {
	id, err := binaryIdentity(h.Binary)
	if err != nil {
		return true, err
	}
	rows, err := records[runFence](h.RunIDFile)
	if err != nil {
		return true, err
	}
	for _, row := range rows {
		if row.identity() != id {
			continue
		}
		installed, err := strconv.ParseUint(row.RunID, 10, 64)
		if err != nil {
			return true, err
		}
		next, _ := strconv.ParseUint(runID, 10, 64)
		return next <= installed, nil
	}
	return false, nil
}

func (h *Handler) install(ctx context.Context, binary Binary, sha string, claims Claims) error {
	next := h.Binary + ".next"
	data, err := h.download(ctx, binary.URL)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != binary.SHA256 {
		return &integrityError{errors.New("downloaded binary sha256 differs")}
	}
	defer os.Remove(next)
	if err := writeSynced(next, data); err != nil {
		return err
	}
	if err := secretpreflight.Check(ctx, next); err != nil {
		return &preflightError{err}
	}
	candidate, err := binaryIdentity(next)
	if err != nil {
		return err
	}
	if candidate.SHA != sha || candidate.SHA256 != binary.SHA256 {
		return &integrityError{errors.New("candidate revision or digest differs from signed release")}
	}
	if err := prepareRecords(h, candidate, claims.RunID, claims.RunAttempt); err != nil {
		return err
	}
	if err := os.Rename(next, h.Binary); err != nil {
		return err
	}
	h.exitOnce.Do(func() { h.exitAfter(WorkerReplyWait + 10*time.Second) })
	if err := syncDirectory(filepath.Dir(h.Binary)); err != nil {
		slog.Warn("release installed; binary rename durability not confirmed", "error", err)
	}
	return nil
}

var downloadStall = 30 * time.Second

func (h *Handler) download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stall := time.AfterFunc(downloadStall, cancel)
	defer stall.Stop()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := h.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(progress{response.Body, func() { stall.Reset(downloadStall) }}, maxBinaryBytes+1))
	if err == nil && len(data) > maxBinaryBytes {
		err = errors.New("binary too large")
	}
	return data, err
}

type progress struct {
	io.Reader
	advanced func()
}

func (p progress) Read(b []byte) (int, error) {
	n, err := p.Reader.Read(b)
	if n > 0 {
		p.advanced()
	}
	return n, err
}

func writeSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	err = errors.Join(err, file.Chmod(0o755), file.Sync(), file.Close())
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func (h *Handler) app(ctx context.Context, data []byte) Reply {
	var release AppRelease
	if err := protocol.DecodeStrict(data, &release, 64<<10); err != nil {
		return rejected(err)
	}
	claims, err := h.validateApp(ctx, release)
	if err != nil {
		return rejected(err)
	}
	if h.App == nil {
		return rejected(errors.New("this host runs no mesh"))
	}
	return h.appOperation(release, claims)
}

func (h *Handler) validateApp(ctx context.Context, release AppRelease) (Claims, error) {
	match := appImage.FindStringSubmatch(release.Image)
	packageName := release.Service
	if release.Service == "ts-dashboard" {
		packageName = "terrascale-dashboard"
	}
	if match == nil || match[1] != packageName {
		return Claims{}, errors.New("image must use the service GHCR package pinned by sha256 digest")
	}
	claims, err := h.Verifier.Verify(ctx, release.Token)
	if err != nil {
		return Claims{}, err
	}
	if !slices.Contains(appServices[claims.JobWorkflowRef], release.Service) {
		return Claims{}, errors.New("token workflow may not release " + release.Service)
	}
	if !hex40.MatchString(claims.SHA) {
		return Claims{}, errors.New("token sha must be 40 lowercase hex")
	}
	return claims, nil
}

func (h *Handler) mesh(ctx context.Context, op string, data []byte) Reply {
	var request MeshRequest
	if err := protocol.DecodeStrict(data, &request, 64<<10); err != nil {
		return rejected(err)
	}
	claims, err := h.Verifier.VerifyMesh(ctx, request.Token)
	if err != nil {
		return rejected(err)
	}
	if claims.JobWorkflowRef != meshWorkflow && op != "state" {
		return rejected(errors.New("the app-digests workflow may only read state"))
	}
	if h.Mesh == nil {
		return rejected(errors.New("this host runs no mesh bridge"))
	}
	if op == "apply" {
		key := appOperationKey{claims.Repository, claims.RunID, claims.RunAttempt, claims.SHA, claims.JobWorkflowRef, "mesh-apply", fmt.Sprintf("%x", sha256.Sum256(request.Spec))}
		return h.operation(key, func(ctx context.Context, _ Progress) (json.RawMessage, error) { return h.Mesh(ctx, op, request.Spec) })
	}
	result, err := h.Mesh(ctx, op, request.Spec)
	if err != nil {
		return Reply{State: "failed", Error: err.Error(), Result: result}
	}
	return Reply{State: "done", Result: result}
}

func (h *Handler) exitAfter(delay time.Duration) {
	if h.runningBinary != h.Binary {
		return
	}
	time.AfterFunc(delay, func() { os.Exit(0) })
}
