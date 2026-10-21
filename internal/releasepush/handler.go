package releasepush

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	SubjectVersion = "ts.release.version"
	SubjectOrch    = "ts.release.ts-orch"
	SubjectApp     = "ts.release.app"

	orchRepository = owner + "/ts-orchestrator"
	downloadPrefix = "https://github.com/" + orchRepository + "/releases/download/"
	assetPrefix    = "terrascale-orchestrator-linux-"
	maxBinaryBytes = 512 << 20
)

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

// Reply answers every release request.
type Reply struct {
	State   string `json:"state,omitempty"` // current, installed, stale, rejected
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
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
	Client    *http.Client
	// App updates a service's image. TODO(slice B): pre-pull the image and
	// update the single-host service (swarmruntime.DialSingleHost +
	// ApplyServiceSpec); nil refuses app releases.
	App func(ctx context.Context, release AppRelease) error
	// Installed receives once after a new binary is in place; the caller exits
	// so systemd restarts the new binary.
	Installed chan struct{}

	mu      sync.Mutex
	pending string // installed, waiting for the restart
}

// NewHandler serves this process's release for the binary it runs from.
func NewHandler(state string) (*Handler, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if executable, err = filepath.EvalSymlinks(executable); err != nil {
		return nil, err
	}
	return &Handler{Verifier: NewVerifier(), Revision: Revision(), Binary: executable,
		RunIDFile: filepath.Join(state, "nats", "release-run-id"),
		Client:    &http.Client{Timeout: 60 * time.Second}, Installed: make(chan struct{}, 1)}, nil
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
		SubjectVersion: func(context.Context, []byte) Reply { return Reply{Version: h.Revision} },
		SubjectOrch:    h.orch,
		SubjectApp:     h.app,
	} {
		if _, err := conn.Subscribe(subject, func(m *nats.Msg) {
			// Each request runs on its own goroutine so a download never blocks version polls.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				reply := handle(ctx, m.Data)
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
	if stale, err := h.olderRun(claims.RunID); err != nil {
		return rejected(err)
	} else if stale {
		return Reply{State: "stale", Error: "a newer run is installed"}
	}
	if err := h.install(ctx, binary); err != nil {
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
	if claims.Repository != orchRepository || claims.SHA != release.SHA {
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

// install downloads, verifies and atomically swaps the binary, keeping the
// previous one as <binary>.prev.
func (h *Handler) install(ctx context.Context, binary Binary) error {
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
	prev := h.Binary + ".prev"
	if err := os.Remove(prev); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Link(h.Binary, prev); err != nil {
		return err
	}
	if err := os.Rename(next, h.Binary); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(h.Binary))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (h *Handler) download(ctx context.Context, url string) ([]byte, error) {
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
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBinaryBytes+1))
	if err == nil && len(data) > maxBinaryBytes {
		err = errors.New("binary too large")
	}
	return data, err
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
	if err := h.validateApp(ctx, release); err != nil {
		return rejected(err)
	}
	if h.App == nil {
		return rejected(errors.New("app releases are not wired yet"))
	}
	if err := h.App(ctx, release); err != nil {
		return rejected(err)
	}
	return Reply{State: "installed"}
}

// validateApp admits a ghcr.io/terrascale/<name> image only with a token from
// the TerraScale repository of the same name.
func (h *Handler) validateApp(ctx context.Context, release AppRelease) error {
	match := appImage.FindStringSubmatch(release.Image)
	if match == nil || release.Service == "" {
		return errors.New("image must be ghcr.io/terrascale/<name>@sha256:<64 hex>")
	}
	claims, err := h.Verifier.Verify(ctx, release.Token)
	if err != nil {
		return err
	}
	if !strings.EqualFold(claims.Repository, owner+"/"+match[1]) {
		return errors.New("token repository does not own the image")
	}
	return nil
}
