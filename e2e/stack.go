package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	tb "terrascale.tech/sdk/v1"
)

//go:embed pins.json
var localPinsJSON []byte

type localPins struct {
	TerraBase struct{ Commit, Release, SHA256 string }
	Sources   map[string]string
	Pending   struct{ Auth, Dashboard string }
}

// startLocal builds verified sources in an owned directory. No service inherits
// production settings, and the only HTTP mutation is loopback key bootstrap.
func startLocal(ctx context.Context) (_ *environment, teardown func() error, err error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, nil, errors.New("local stack requires the pinned linux/amd64 TerraBase artifact")
	}
	var pins localPins
	if err = json.Unmarshal(localPinsJSON, &pins); err != nil {
		return nil, nil, err
	}
	cache := os.Getenv("E2E_CACHE")
	if cache == "" {
		cache, err = os.UserCacheDir()
		if err != nil {
			return nil, nil, err
		}
		cache = filepath.Join(cache, "terrascale", "e2e")
	}
	cache, err = filepath.Abs(cache)
	if err != nil {
		return nil, nil, err
	}
	if err = os.MkdirAll(cache, 0700); err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp(cache, "run-")
	if err != nil {
		return nil, nil, err
	}
	var children []*localProcess
	var once sync.Once
	var cleanupErr error
	teardown = func() error {
		once.Do(func() {
			for i := len(children) - 1; i >= 0; i-- {
				cleanupErr = errors.Join(cleanupErr, children[i].stop())
			}
			cleanupErr = errors.Join(cleanupErr, os.RemoveAll(dir))
		})
		return cleanupErr
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, teardown())
		}
	}()
	startup, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	bin, err := localTerraBaseBinary(startup, cache, pins)
	if err != nil {
		return nil, teardown, err
	}
	certFile, keyFile, pool, err := localCertificate(dir)
	if err != nil {
		return nil, teardown, err
	}
	e := &environment{Target: "local", Region: "local-1", Credential: rand.Text() + rand.Text(), UserID: "ts512-" + rand.Text(), HTTP: &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	credFile := filepath.Join(dir, "dashboard-credential")
	if err = os.WriteFile(credFile, []byte(e.Credential+"\n"), 0600); err != nil {
		return nil, teardown, err
	}
	base, err := startLocalProcess(dir, append(localEnv(), "TERRABASE_REGION="+e.Region), bin,
		"--admin-port=0", "--client-port=0", "--client-certificate="+certFile, "--client-private-key="+keyFile,
		"--dashboard-credential-file="+credFile, "--data-directory="+filepath.Join(dir, "data"))
	if err != nil {
		return nil, teardown, err
	}
	children = append(children, base)
	err = waitLocal(startup, base, func() bool {
		for line := range strings.SplitSeq(base.output.String(), "\n") {
			if raw, ok := strings.CutPrefix(strings.TrimSpace(line), "Now listening on: "); ok {
				u, parseErr := url.Parse(raw)
				if parseErr != nil || u.Port() == "" {
					continue
				}
				switch u.Scheme {
				case "http":
					e.AdminURL = "http://127.0.0.1:" + u.Port()
				case "https":
					e.TerraBaseURL = "https://localhost:" + u.Port()
				}
			}
		}
		return e.AdminURL != "" && e.TerraBaseURL != "" && probe(startup, e, e.AdminURL, "/healthz") == nil
	})
	if err != nil {
		return nil, teardown, fmt.Errorf("TerraBase startup: %w", err)
	}
	management, err := tb.NewManagement(tb.Config{BaseURL: e.TerraBaseURL, Token: e.Credential, HTTPClient: e.HTTP, MaxRetries: -1})
	if err != nil {
		return nil, teardown, err
	}
	user := management.As(e.UserID)
	org, err := user.CreateOrganization(startup, "terrascale-internal")
	if err != nil {
		return nil, teardown, fmt.Errorf("internal organization bootstrap: %w", err)
	}
	e.OrganizationID = org.ID
	project, err := user.CreateProject(startup, org.ID, "internal-services")
	if err != nil {
		return nil, teardown, err
	}
	for _, name := range []string{"ts-auth", "ts-dashboard"} {
		if _, err = user.CreateDatabase(startup, org.ID, project.ID, name); err != nil {
			return nil, teardown, err
		}
	}
	e.APIKey, err = issueLocalKey(startup, e, org.ID, project.ID)
	if err != nil {
		return nil, teardown, err
	}
	// These are fresh checkouts, never the developer's sibling working trees.
	sources := filepath.Join(dir, "sources")
	for _, name := range []string{"ts-dotnet", "ts-libs", "ts-auth", "ts-dashboard"} {
		if err = localSource(startup, sources, cache, name, pins.Sources[name]); err != nil {
			return nil, teardown, err
		}
	}
	authDir := filepath.Join(sources, "ts-auth")
	authOut := filepath.Join(dir, "auth-build")
	buildEnv := append(localEnv(), "DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1", "TerraScaleRoot="+sources)
	if err = localCommand(startup, authDir, buildEnv, "dotnet", "publish", "src/TerraScale.Auth/TerraScale.Auth.csproj",
		"-c", "Release", "-r", "linux-x64", "--self-contained", "true", "-o", authOut, "-p:RestoreLockedMode=true",
		"-p:PublishSingleFile=true", "-p:IncludeNativeLibrariesForSelfExtract=true", "-p:TS_AUTH_REVISION="+pins.Sources["ts-auth"]); err != nil {
		return nil, teardown, fmt.Errorf("build pinned auth and dependencies: %w", err)
	}
	master := make([]byte, 32)
	if _, err = rand.Read(master); err != nil {
		return nil, teardown, err
	}
	authEnv := append(localEnv(), "TS_AUTH_ENVIRONMENT=Development", "TS_AUTH_LISTEN=http://127.0.0.1:0",
		"TS_AUTH_PUBLIC_ORIGIN=http://localhost", "TS_AUTH_TERRASCALE_API_URL="+e.TerraBaseURL,
		"TS_AUTH_TERRASCALE_API_KEY="+e.APIKey, "TS_AUTH_TERRASCALE_TENANT_ID="+org.ID,
		"TS_AUTH_TERRASCALE_PROJECT_ID="+project.ID, "TS_AUTH_DATABASE=ts-auth",
		"TS_AUTH_MASTER_KEY="+base64.StdEncoding.EncodeToString(master), "TS_AUTH_OPERATOR_KEY="+rand.Text()+rand.Text(),
		"SSL_CERT_FILE="+certFile)
	auth, err := startLocalProcess(authDir, authEnv, filepath.Join(authOut, "ts-auth"))
	if err != nil {
		return nil, teardown, err
	}
	children = append(children, auth)
	err = waitLocal(startup, auth, func() bool {
		for line := range strings.SplitSeq(auth.output.String(), "\n") {
			if raw, ok := strings.CutPrefix(strings.TrimSpace(line), "Now listening on: "); ok {
				if u, parseErr := url.Parse(raw); parseErr == nil && u.Scheme == "http" && u.Port() != "" {
					e.AuthURL = "http://127.0.0.1:" + u.Port()
				}
			}
		}
		return e.AuthURL != "" && probe(startup, e, e.AuthURL, "/healthz") == nil
	})
	if err != nil {
		return nil, teardown, fmt.Errorf("auth startup: %w", err)
	}
	// The real scenario still requests /readyz. This marker only explains the
	// pinned implementation's exact not_ready response, never other failures.
	e.AuthUnavailable = pins.Pending.Auth
	dashboardDir := filepath.Join(sources, "ts-dashboard")
	for _, args := range [][]string{{"ci", "--no-audit", "--no-fund"}, {"run", "build:css"}, {"run", "build:js"}} {
		if err = localCommand(startup, dashboardDir, localEnv(), "npm", args...); err != nil {
			return nil, teardown, fmt.Errorf("build pinned dashboard assets: %w", err)
		}
	}
	goEnv := append(localEnv(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOFLAGS=-mod=vendor")
	if err = localCommand(startup, dashboardDir, goEnv, "go", "tool", "templ", "generate", "-path", "internal", "-include-version=false", "-include-timestamp=false", "-check"); err != nil {
		return nil, teardown, fmt.Errorf("check pinned dashboard templates: %w", err)
	}
	dashboardBin := filepath.Join(dir, "dashboard")
	if err = localCommand(startup, dashboardDir, goEnv,
		"go", "build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-ldflags=-X terrascale.tech/dashboard/internal/platform/buildinfo.version="+pins.Sources["ts-dashboard"], "-o", dashboardBin, "./cmd/dashboard"); err != nil {
		return nil, teardown, fmt.Errorf("build pinned dashboard: %w", err)
	}
	// No demo setting is supplied: the current release must reject live mode.
	dashboard, err := startLocalProcess(dashboardDir, append(localEnv(), "DASHBOARD_ADDR=127.0.0.1:0", "DASHBOARD_DEV=1",
		"TS_API_BASE_URL="+e.TerraBaseURL, "TS_API_ACCESS_TOKEN="+e.APIKey, "DASHBOARD_STATUS_SUMMARY_URL=", "SSL_CERT_FILE="+certFile), dashboardBin)
	if err != nil {
		return nil, teardown, err
	}
	children = append(children, dashboard)
	select {
	case <-dashboard.done:
		const expected = "error=\"invalid configuration: live dashboard persistence is not configured; set TS_DASHBOARD_PRODUCTION_DEMO=1\""
		var exit *exec.ExitError
		if !errors.As(dashboard.waitErr, &exit) || exit.ExitCode() != 1 || !strings.Contains(dashboard.output.String(), expected) {
			return nil, teardown, errors.New("dashboard failed unexpectedly; process output withheld to protect credentials")
		}
		dashboard.expectedExit = true
		e.DashboardUnavailable = pins.Pending.Dashboard
	case <-time.After(30 * time.Second):
		return nil, teardown, errors.New("pinned dashboard did not report its expected live-store rejection within 30 seconds")
	case <-startup.Done():
		return nil, teardown, startup.Err()
	}
	return e, teardown, nil
}

func localTerraBaseBinary(ctx context.Context, cache string, pins localPins) (string, error) {
	path := os.Getenv("E2E_TERRABASE_BINARY")
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		// Install a verified owned copy; downloaded overrides need not already
		// be executable, and the caller's artifact is never mutated.
		return installLocalBinary(f, cache, pins)
	}
	path = filepath.Join(cache, "terrabase-"+pins.TerraBase.Commit)
	if err := verifyLocalBinary(path, pins.TerraBase.SHA256); err == nil {
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://git.terrascale.tech/TerraScale/terrabase/releases/download/"+pins.TerraBase.Release+"/terrabase-linux-amd64", nil)
	if err != nil {
		return "", err
	}
	if token := envDefault("TERRABASE_TOKEN", os.Getenv("E2E_FORGEJO_TOKEN")); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download pinned TerraBase: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download pinned TerraBase: HTTP %d (TERRABASE_TOKEN or E2E_FORGEJO_TOKEN may be required)", res.StatusCode)
	}
	return installLocalBinary(res.Body, cache, pins)
}

func installLocalBinary(source io.Reader, cache string, pins localPins) (string, error) {
	tmp, err := os.CreateTemp(cache, ".terrabase-")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	_, copyErr := io.Copy(tmp, io.LimitReader(source, 512<<20))
	err = errors.Join(copyErr, tmp.Close())
	if err != nil {
		return "", err
	}
	if err = verifyLocalBinary(tmp.Name(), pins.TerraBase.SHA256); err != nil {
		return "", err
	}
	if err = os.Chmod(tmp.Name(), 0700); err != nil {
		return "", err
	}
	path := filepath.Join(cache, "terrabase-"+pins.TerraBase.Commit)
	return path, os.Rename(tmp.Name(), path)
}

func verifyLocalBinary(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("TerraBase binary SHA-256 does not match pins.json")
	}
	return nil
}

func localSource(ctx context.Context, root, cache, name, revision string) error {
	if len(revision) != 40 {
		return fmt.Errorf("missing full source revision for %s", name)
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return fmt.Errorf("invalid source revision for %s", name)
	}
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	askpass := filepath.Join(root, ".askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\ncase \"$1\" in Username*) printf '%s\\n' oauth2 ;; *) printf '%s\\n' \"$E2E_SOURCE_TOKEN\" ;; esac\n"), 0700); err != nil {
		return err
	}
	defer os.Remove(askpass)
	env := append(localEnv(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS="+askpass,
		"E2E_SOURCE_TOKEN="+envDefault("E2E_FORGEJO_TOKEN", os.Getenv("TERRABASE_TOKEN")))
	repo := filepath.Join(cache, "git", name+"-"+revision+".git")
	if err := os.MkdirAll(repo, 0700); err != nil {
		return err
	}
	if err := localCommand(ctx, repo, env, "git", "init", "-q", "--bare"); err != nil {
		return err
	}
	// Git object IDs verify cached inputs. Builds always get a fresh checkout,
	// so cached working-tree edits and untracked files cannot affect them.
	check := exec.CommandContext(ctx, "git", "--git-dir="+repo, "rev-parse", "--verify", revision+"^{commit}")
	check.Env = env
	verified, checkErr := check.Output()
	if checkErr != nil || strings.TrimSpace(string(verified)) != revision {
		if err := localCommand(ctx, repo, env, "git", "-c", "credential.helper=", "fetch", "-q", "--depth=1", "https://git.terrascale.tech/TerraScale/"+name+".git", revision); err != nil {
			return fmt.Errorf("fetch pinned %s source (E2E_FORGEJO_TOKEN or TERRABASE_TOKEN may be required): %w", name, err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"fetch", "-q", "--depth=1", repo, revision}, {"checkout", "-q", "--detach", "FETCH_HEAD"}} {
		if err := localCommand(ctx, dir, env, "git", args...); err != nil {
			return fmt.Errorf("checkout pinned %s source: %w", name, err)
		}
	}
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir, cmd.Env = dir, env
	output, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(output)) != revision {
		return fmt.Errorf("%s checkout does not match pinned revision", name)
	}
	return nil
}

// Keep only toolchain essentials. Service credentials and external integrations
// from the caller cannot accidentally select a production dependency.
func localEnv() []string {
	var env []string
	for _, key := range []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "DOTNET_ROOT", "DOTNET_MULTILEVEL_LOOKUP", "LD_LIBRARY_PATH", "NIX_LD", "NIX_LD_LIBRARY_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "NIX_SSL_CERT_FILE", "CI"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func localCommand(ctx context.Context, dir string, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = dir, env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	// Build/fetch output may contain credentials. Do not print it on failure.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w (output withheld)", name, err)
	}
	return nil
}

type localProcess struct {
	cmd          *exec.Cmd
	output       localOutput
	done         chan struct{}
	waitErr      error
	expectedExit bool
}

func startLocalProcess(dir string, env []string, name string, args ...string) (*localProcess, error) {
	p := &localProcess{cmd: exec.Command(name, args...), done: make(chan struct{})}
	p.cmd.Dir, p.cmd.Env = dir, env
	p.cmd.Stdout, p.cmd.Stderr = &p.output, &p.output
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	p.cmd.WaitDelay = 5 * time.Second
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", filepath.Base(name), err)
	}
	go func() { p.waitErr = p.cmd.Wait(); close(p.done) }()
	return p, nil
}

func (p *localProcess) stop() error {
	select {
	case <-p.done:
		if p.expectedExit {
			return nil
		}
		return fmt.Errorf("%s exited unexpectedly before teardown: %v", filepath.Base(p.cmd.Path), p.waitErr)
	default:
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
		return nil
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	}
	select {
	case <-p.done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("local child did not exit after termination")
	}
}

func waitLocal(ctx context.Context, p *localProcess, ready func() bool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return errors.New("process exited before readiness; output withheld")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if ready() {
				return nil
			}
		}
	}
}

// Logs are kept privately only to discover assigned ports and exact startup
// rejection. Bound memory even if a service repeatedly logs an error.
type localOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (o *localOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(p)
	if remaining := (1 << 20) - o.b.Len(); remaining > 0 {
		_, _ = o.b.Write(p[:min(remaining, n)])
	}
	return n, nil
}

func (o *localOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

func localCertificate(dir string) (certFile, keyFile string, pool *x509.CertPool, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", nil, err
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(certFile, certPEM, 0600); err != nil {
		return "", "", nil, err
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return "", "", nil, err
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return certFile, keyFile, pool, nil
}
