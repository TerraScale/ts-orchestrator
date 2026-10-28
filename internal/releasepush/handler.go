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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	SubjectVersion = protocol.ReleaseVersion
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

// HandlerWait bounds one release request: three regions rolled in turn, each
// up to a 180 s readiness timeout and bounded bake recovery, plus overhead.
const HandlerWait = 25 * time.Minute

var (
	hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// appImage is a TerraScale GHCR image pinned by digest; group 1 is its name.
	appImage = regexp.MustCompile(`^ghcr\.io/terrascale/([a-z0-9][a-z0-9._-]{0,127})@sha256:[0-9a-f]{64}$`)
)

// Binary is one architecture's release asset.
type Binary struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// OrchRelease is the ts.release.ts-orch request; Binaries is keyed by GOARCH.
type OrchRelease struct {
	SHA      string            `json:"sha"`
	Binaries map[string]Binary `json:"binaries"`
	Token    string            `json:"token"`
}

// AppRelease is the ts.release.app request: one service's new image.
type AppRelease struct {
	Service string `json:"service"`
	Image   string `json:"image"`
	Token   string `json:"token"`
}

// MeshRequest is the ts.release.mesh.ping, .apply and .rm request;
// Spec is the service to apply.
type MeshRequest struct {
	Token string          `json:"token"`
	Spec  json.RawMessage `json:"spec,omitempty"`
}

// Reply answers every release request.
type Reply struct {
	State   string `json:"state,omitempty"` // current, installed, stale, rolled_back, rejected; done, failed for mesh
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	// RolledBack is the release this host restored <binary>.prev over; Error says why.
	RolledBack string `json:"rolled_back,omitempty"`
	// Result is the mesh's per-region rows.
	Result json.RawMessage `json:"result,omitempty"`
}

// Handler serves the release subjects on any connection with full permissions.
type Handler struct {
	Verifier *Verifier
	// Revision is the running build's vcs.revision.
	Revision string
	// Binary is the installed executable that a release replaces.
	Binary string
	// RunIDFile records the installed release's GitHub run_id; an older run is refused.
	RunIDFile string
	// TrialFile is the probation marker install writes (Probe); RollbackFile
	// records the last release that never served.
	TrialFile, RollbackFile string
	Client                  *http.Client
	// App swaps service's image in every region (rolling back on failure) and
	// returns the per-region rows, also when it fails; nil refuses app releases.
	App func(ctx context.Context, service, image string, claims Claims) (json.RawMessage, error)
	// Mesh runs a multi-region workflow request (op "ping" or "apply") on the
	// cross-region mesh and returns its rows, also when it fails; nil refuses them.
	Mesh func(ctx context.Context, op string, spec json.RawMessage) (json.RawMessage, error)
	// Installed receives once after a new binary is in place; the caller exits
	// so systemd restarts the new binary.
	Installed chan struct{}

	mu            sync.Mutex
	pending       string // installed, waiting for the restart
	rolledBack    atomic.Pointer[Rollback]
	appOperations map[appOperationKey]*appOperation
}

// NewHandler serves this process's release for the binary it runs from.
func NewHandler(state string) (*Handler, error) {
	binary, err := executable()
	if err != nil {
		return nil, err
	}
	h := &Handler{Verifier: NewVerifier(), Revision: Revision(), Binary: binary,
		RunIDFile: filepath.Join(state, "nats", "release-run-id"), TrialFile: trialFile(state), RollbackFile: rollbackFile(state),
		Client: &http.Client{}, Installed: make(chan struct{}, 1)}
	h.rolledBack.Store(readRollback(h.RollbackFile))
	return h, nil
}

// executable is the real path of the running binary, which a release replaces.
func executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

// Revision is the running binary's full vcs.revision ("-dirty" when modified).
func Revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	revision, modified := "unknown", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}

// Serve subscribes the release subjects until the connection closes.
func (h *Handler) Serve(conn *nats.Conn) error {
	for subject, handle := range map[string]func(context.Context, []byte) Reply{
		SubjectVersion: func(context.Context, []byte) Reply { return h.version() },
		SubjectOrch:    h.orch,
		SubjectApp:     h.app,
		SubjectPing:    func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "ping", data) },
		SubjectApply:   func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "apply", data) },
		SubjectRemove:  func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "rm", data) },
		SubjectState:   func(ctx context.Context, data []byte) Reply { return h.mesh(ctx, "state", data) },
	} {
		if _, err := conn.Subscribe(subject, func(m *nats.Msg) {
			// Each request runs on its own goroutine so a download never blocks version polls.
			go func() {
				// A region-by-region rollout takes each region's readiness timeout in turn.
				ctx, cancel := context.WithTimeout(context.Background(), HandlerWait)
				defer cancel()
				reply := handle(ctx, m.Data)
				if reply.Error != "" {
					// The pusher may have stopped waiting (fra 2026-10-28 20:13Z):
					// the host keeps the reason.
					slog.Warn("release request failed", "subject", subject, "state", reply.State, "error", reply.Error)
				}
				data, _ := json.Marshal(reply)
				_ = m.Respond(data)
				if reply.State == "installed" {
					_ = conn.Flush()
					select {
					case h.Installed <- struct{}{}:
					default:
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
	if rollback := h.rolledBack.Load(); rollback != nil {
		return Reply{Version: h.Revision, RolledBack: rollback.SHA, Error: rollback.Reason}
	}
	return Reply{Version: h.Revision}
}

func (h *Handler) orch(ctx context.Context, data []byte) Reply {
	var release OrchRelease
	if err := protocol.DecodeStrict(data, &release, 64<<10); err != nil {
		return rejected(err)
	}
	binary, claims, err := h.validateOrch(ctx, release)
	if err != nil {
		return rejected(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if release.SHA == h.Revision {
		return Reply{State: "current", Version: h.Revision}
	}
	if release.SHA == h.pending {
		return Reply{State: "installed", Version: release.SHA}
	}
	// A retry of the run that never served is refused; a newer run may try again.
	if rollback := h.rolledBack.Load(); rollback != nil && rollback.SHA == release.SHA && rollback.RunID == claims.RunID {
		return Reply{State: "rolled_back", Version: h.Revision, RolledBack: rollback.SHA, Error: rollback.Reason}
	}
	if stale, err := h.olderRun(claims.RunID); err != nil {
		return rejected(err)
	} else if stale {
		return Reply{State: "stale", Error: "a newer run is installed"}
	}
	// The marker precedes the swap, so the new binary's first start is on
	// probation; its clock starts after the download.
	if err := h.install(ctx, binary, func() error {
		return writeJSON(h.TrialFile, trial{SHA: release.SHA, RunID: claims.RunID, Installed: time.Now()})
	}); err != nil {
		return rejected(errors.Join(err, removeIfExists(h.TrialFile)))
	}
	h.rolledBack.Store(nil)
	if err := removeIfExists(h.RollbackFile); err != nil {
		return rejected(err)
	}
	if err := os.WriteFile(h.RunIDFile, []byte(claims.RunID), 0o600); err != nil {
		return rejected(err)
	}
	h.pending = release.SHA
	return Reply{State: "installed", Version: release.SHA}
}

// ReleaseTag is the GitHub release CI run runID publishes for sha.
func ReleaseTag(sha, runID string) string { return "ci-" + sha + "-run-" + runID }

// ReleaseURL is that release's binary for arch.
func ReleaseURL(sha, runID, arch string) string {
	return downloadPrefix + ReleaseTag(sha, runID) + "/" + assetPrefix + arch
}

// validateOrch checks the request and its signature; it returns this host's asset.
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
		return Binary{}, Claims{}, err
	}
	if claims.JobWorkflowRef != orchWorkflow || claims.SHA != release.SHA {
		return Binary{}, Claims{}, errors.New("token is not for this ts-orchestrator commit")
	}
	// The URL is unsigned: only the signed run's own release asset is accepted,
	// so a captured token cannot install another build under its sha.
	if want := ReleaseURL(release.SHA, claims.RunID, runtime.GOARCH); binary.URL != want {
		return Binary{}, Claims{}, errors.New("url must be " + want)
	}
	return binary, claims, nil
}

func (h *Handler) olderRun(runID string) (bool, error) {
	data, err := os.ReadFile(h.RunIDFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	installed, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return true, err
	}
	next, _ := strconv.ParseUint(runID, 10, 64)
	return next < installed, nil
}

// link is os.Link; tests stand in an immutable binary.
var link = os.Link

// install downloads and verifies the binary, runs beforeSwap, then atomically
// swaps it in, keeping the previous one as <binary>.prev. A failed swap leaves
// no <binary>.next.
func (h *Handler) install(ctx context.Context, binary Binary, beforeSwap func() error) error {
	next := h.Binary + ".next"
	data, err := h.download(ctx, binary.URL)
	if err != nil {
		// One immediate retry: no sleeps on the release path.
		if data, err = h.download(ctx, binary.URL); err != nil {
			return err
		}
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != binary.SHA256 {
		return errors.New("downloaded binary sha256 differs")
	}
	if err := writeSynced(next, data); err != nil {
		return err
	}
	if err := beforeSwap(); err != nil {
		return errors.Join(err, removeIfExists(next))
	}
	prev := h.Binary + ".prev"
	err = removeIfExists(prev)
	if err == nil {
		err = link(h.Binary, prev)
	}
	if err == nil {
		err = os.Rename(next, h.Binary)
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			err = fmt.Errorf("%w (an immutable binary refuses replacement: run `chattr -i %s %s` on the host)", err, h.Binary, prev)
		}
		return errors.Join(err, removeIfExists(next))
	}
	dir, err := os.Open(filepath.Dir(h.Binary))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// downloadStall cancels a binary download that receives nothing for this
// long. A whole-download timeout (60 s) failed fra's 110 MB download on
// 2026-10-28 20:11Z while its CPU was saturated; a slow one now finishes.
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

// progress calls advanced after every read that returns data.
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

// validateApp admits only ghcr.io/terrascale/<service>@sha256:<digest> with a
// token from a workflow appServices allows to release service.
func (h *Handler) validateApp(ctx context.Context, release AppRelease) (Claims, error) {
	match := appImage.FindStringSubmatch(release.Image)
	if match == nil || match[1] != release.Service {
		return Claims{}, errors.New("image must be ghcr.io/terrascale/<service>@sha256:<64 hex>")
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

// mesh admits ts-orchestrator's multi-region workflow tokens, and
// app-digests tokens for state only.
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
		return h.operation(key, func(ctx context.Context) (json.RawMessage, error) { return h.Mesh(ctx, op, request.Spec) })
	}
	result, err := h.Mesh(ctx, op, request.Spec)
	if err != nil {
		return Reply{State: "failed", Error: err.Error(), Result: result}
	}
	return Reply{State: "done", Result: result}
}
