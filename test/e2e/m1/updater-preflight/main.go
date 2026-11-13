package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/nats-io/nats.go"
)

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(path, value string) {
	must(os.MkdirAll(filepath.Dir(path), 0o750))
	must(os.WriteFile(path, []byte(value), 0o640))
}

func stop(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func ready(cmd *exec.Cmd, marker string) {
	pipe, err := cmd.StdoutPipe()
	must(err)
	cmd.Stderr = cmd.Stdout
	must(cmd.Start())
	scanner := bufio.NewScanner(pipe)
	var seen []string
	for scanner.Scan() {
		seen = append(seen, scanner.Text())
		if strings.Contains(scanner.Text(), marker) {
			go io.Copy(io.Discard, pipe)
			return
		}
	}
	panic("process did not announce " + marker + ":\n" + strings.Join(seen[max(0, len(seen)-40):], "\n"))
}

type corruptTransport struct{ base http.RoundTripper }

func (t corruptTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(append(data, 0)))
	return response, nil
}

type providerTransport struct{ url string }

func (p providerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	local, err := http.NewRequestWithContext(request.Context(), request.Method, p.url, nil)
	if err != nil {
		return nil, err
	}
	clone.URL, clone.Host = local.URL, local.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func signedRelease(ctx context.Context, binary, sha, run, attempt string) (releasepush.OrchRelease, *releasepush.Verifier, *http.Client, func()) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	data, err := os.ReadFile(binary)
	must(err)
	sum := sha256.Sum256(data)
	issuedToken := ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]string{"value": issuedToken})
			return
		}
		if r.URL.Path == "/jwks" {
			must(json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
				"kty": "RSA", "kid": "e2e", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}}))
			return
		}
		_, _ = w.Write(data)
	}))
	claims, err := json.Marshal(map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch", "exp": time.Now().Add(time.Hour).Unix(),
		"repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale", "ref": "refs/heads/main",
		"sha": sha, "run_id": run, "run_attempt": attempt, "event_name": "push", "workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main",
	})
	must(err)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"e2e"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	must(err)
	issuedToken = unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	release := releasepush.OrchRelease{SHA: sha, Token: unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), Binaries: map[string]releasepush.Binary{
		runtime.GOARCH: {URL: releasepush.ReleaseURL(sha, run, runtime.GOARCH), SHA256: hex.EncodeToString(sum[:])},
	}}
	verifier := releasepush.NewVerifier()
	verifier.JWKSURL = provider.URL + "/jwks"
	_, err = verifier.Verify(ctx, release.Token)
	must(err)
	return release, verifier, &http.Client{Transport: providerTransport{provider.URL + "/binary"}}, provider.Close
}

func request(ctx context.Context, conn *nats.Conn, subject string, payload []byte) releasepush.Reply {
	message, err := conn.RequestWithContext(ctx, subject, payload)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
}

func candidateMode() string {
	path, err := os.Executable()
	must(err)
	data, err := os.ReadFile(path)
	must(err)
	marker := bytes.LastIndex(data, []byte("\nCANDIDATE:"))
	if marker < 0 {
		return ""
	}
	return string(data[marker+len("\nCANDIDATE:"):])
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	if len(os.Args) == 3 && os.Args[1] == "release" && os.Args[2] == "recover" {
		command := exec.CommandContext(ctx, "/opt/agent", "release", "recover")
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		must(command.Run())
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "single-host" {
		if candidateMode() == "early-exit" {
			os.Exit(17)
		}
		h, err := releasepush.NewHandler("/var/lib/ts-orch")
		must(err)
		conn, closeListener := listener(h)
		defer closeListener()
		write("/run/recovery-listener", conn.ConnectedUrl())
		if candidateMode() != "hold" && candidateMode() != "starting" {
			probation, err := releasepush.Probe("/var/lib/ts-orch", os.Stdout)
			must(err)
			require(probation.Served(), "restored updater must confirm")
		}
		if candidateMode() != "starting" {
			must(sdnotify.Process().Ready(""))
		}
		<-ctx.Done()
		return
	}
	if len(os.Args) >= 3 {
		switch os.Args[1] {
		case "recovery-install":
			recoveryInstall(ctx)
			return
		case "recovery-case":
			recoveryCase(ctx, os.Args[2])
			return
		case "commit-case":
			commitCase(ctx, os.Args[2], os.Args[3])
			return
		case "rollback-case":
			stageCase(ctx, os.Args[2], 2, "hold")
			return
		case "confirm-case":
			stageCase(ctx, os.Args[2], 0, "serve")
			return
		case "confirm-last-case":
			stageCase(ctx, os.Args[2], 1, "serve")
			return
		case "replace-case":
			replaceCase(ctx, os.Args[2], false)
			return
		case "damaged-replace-case":
			replaceCase(ctx, os.Args[2], true)
			return
		case "expiry-race-case":
			expiryRaceCase(os.Args[2])
			return
		case "expiry-race-start":
			expiryRaceStart(ctx, os.Args[2])
			return
		case "settle-case":
			settleCase(os.Args[2])
			return
		case "resume-case":
			resumeCase(ctx, os.Args[2], os.Args[3])
			return
		case "start-state":
			startState(ctx, os.Args[2], os.Args[3])
			return
		case "serve-region":
			serveRegion(ctx, os.Args[2:])
			return
		case "self-update":
			selfUpdate(ctx, os.Args[2], os.Args[3])
			return
		}
	}
	if len(os.Args) == 3 && os.Args[1] == "release" && os.Args[2] == "preflight" {
		switch candidateMode() {
		case "refuse":
			fmt.Fprintln(os.Stderr, "candidate refuses this release")
			os.Exit(17)
		case "noise":
			chunk := bytes.Repeat([]byte("abc\x00\x1b\n\xff"), 1024)
			for range (10<<20)/len(chunk) + 1 {
				_, _ = os.Stdout.Write(chunk)
			}
			os.Exit(17)
		case "hang":
			<-time.NewTimer(10 * time.Minute).C
		}
		return
	}
	run(ctx, os.Args[1], os.Args[2])
}
