package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

var (
	shaA = strings.Repeat("a", 40)
	shaB = strings.Repeat("b", 40)
	shaC = strings.Repeat("c", 40)
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

func writeExecutable(path string, data []byte) {
	must(os.WriteFile(path, data, 0o755))
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	must(err)
	return data
}

func record(path string) map[string]any {
	data := read(path)
	if data == nil {
		return nil
	}
	var value map[string]any
	must(json.Unmarshal(data, &value))
	return value
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func temporary(prefix string) (string, func()) {
	path, err := os.MkdirTemp("", prefix)
	must(err)
	return path, func() { must(os.RemoveAll(path)) }
}

func helperBytes() []byte {
	helper, err := os.Executable()
	must(err)
	return read(helper)
}

func helperReadable() bool {
	helper, err := os.Executable()
	must(err)
	_, err = os.ReadFile(helper)
	return err == nil
}

func stamped(data []byte, sha, mode string) []byte {
	before := []byte("vcs.revision=" + releasepush.Revision())
	require(bytes.Contains(data, before), "journey helper must have a clean build revision")
	return append(bytes.ReplaceAll(data, before, []byte("vcs.revision="+sha)), []byte("\nCANDIDATE:"+mode)...)
}

func candidateMode() string {
	if !helperReadable() {
		return "unreadable"
	}
	data := helperBytes()
	marker := bytes.LastIndex(data, []byte("\nCANDIDATE:"))
	if marker < 0 {
		return ""
	}
	mode := data[marker+len("\nCANDIDATE:"):]
	if len(mode) > 4096 || bytes.ContainsAny(mode, "\x00\n") {
		return ""
	}
	return string(mode)
}

func revisionOf(path string) string {
	info, err := buildinfo.ReadFile(path)
	must(err)
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	return "unknown"
}

type entry struct {
	Mode     fs.FileMode
	Content  string
	Modified int64
}

func snapshot(normalize bool, dirs ...string) map[string]entry {
	files := map[string]entry{}
	for index, dir := range dirs {
		must(filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			must(err)
			info, err := os.Lstat(path)
			must(err)
			relative, err := filepath.Rel(dir, path)
			must(err)
			value := entry{Mode: info.Mode()}
			switch {
			case info.Mode()&fs.ModeSymlink != 0:
				target, err := os.Readlink(path)
				must(err)
				value.Content = "-> " + target
			case info.Mode().IsRegular():
				value.Content = digest(read(path))
				if !normalize {
					value.Modified = info.ModTime().UnixNano()
				}
				if normalize && filepath.Base(path) == "release-trial" {
					trial := record(path)
					trial["installed"] = "normalized"
					data, err := json.Marshal(trial)
					must(err)
					value.Content = string(data)
				}
			}
			files[fmt.Sprint(index)+"/"+relative] = value
			return nil
		}))
	}
	return files
}

func sameFiles(a, b map[string]entry) string {
	keys := map[string]bool{}
	for key := range a {
		keys[key] = true
	}
	for key := range b {
		keys[key] = true
	}
	var differ []string
	for key := range keys {
		if a[key] != b[key] {
			differ = append(differ, fmt.Sprintf("%s: %+v != %+v", key, a[key], b[key]))
		}
	}
	slices.Sort(differ)
	return strings.Join(differ, "; ")
}

type provider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	asset  atomic.Pointer[[]byte]
	claims atomic.Pointer[tokenClaims]
	jwks   atomic.Pointer[func(http.ResponseWriter)]
	hits   atomic.Int32
}

type tokenClaims struct{ sha, run, kid string }

func newProvider(asset []byte) *provider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	p := &provider{key: key}
	p.asset.Store(&asset)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			claims := p.claims.Load()
			must(json.NewEncoder(w).Encode(map[string]string{"value": p.mint(*claims, r.URL.Query().Get("audience"))}))
		case "/jwks":
			p.hits.Add(1)
			if serve := p.jwks.Load(); serve != nil {
				(*serve)(w)
				return
			}
			p.keys(w)
		default:
			_, _ = w.Write(*p.asset.Load())
		}
	}))
	return p
}

func (p *provider) keys(w http.ResponseWriter) {
	must(json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": "e2e", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
	}}}))
}

func (p *provider) mint(c tokenClaims, audience string) string {
	claims, err := json.Marshal(map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": audience, "exp": time.Now().Add(time.Hour).Unix(),
		"repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale", "ref": "refs/heads/main",
		"sha": c.sha, "run_id": c.run, "run_attempt": "1", "event_name": "push", "workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main",
	})
	must(err)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"`+c.kid+`"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	must(err)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (p *provider) declaration() string {
	return p.mint(*p.claims.Load(), releasepush.PreflightAudience)
}

func (p *provider) release(sha, run, kid string) releasepush.OrchRelease {
	claims := tokenClaims{sha, run, kid}
	p.claims.Store(&claims)
	return releasepush.OrchRelease{SHA: sha, Token: p.mint(claims, releasepush.Audience), Binaries: map[string]releasepush.Binary{
		runtime.GOARCH: {URL: releasepush.ReleaseURL(sha, run, runtime.GOARCH), SHA256: digest(*p.asset.Load())},
	}}
}

func (p *provider) verifier() *releasepush.Verifier {
	verifier := releasepush.NewVerifier()
	verifier.JWKSURL = p.server.URL + "/jwks"
	return verifier
}

func (p *provider) client() *http.Client {
	return &http.Client{Transport: redirect{p.server.URL + "/binary"}}
}

type redirect struct{ url string }

func (r redirect) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	local, err := http.NewRequestWithContext(request.Context(), request.Method, r.url, nil)
	if err != nil {
		return nil, err
	}
	clone.URL, clone.Host = local.URL, local.Host
	return http.DefaultTransport.RoundTrip(clone)
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

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("host network unavailable")
}

func listener(h *releasepush.Handler) (*nats.Conn, func()) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	must(err)
	go srv.Start()
	require(srv.ReadyForConnections(5*time.Second), "release listener must listen")
	conn, err := nats.Connect(srv.ClientURL())
	must(err)
	must(h.Serve(conn))
	return conn, func() { conn.Close(); srv.Shutdown() }
}

func request(ctx context.Context, conn *nats.Conn, subject string, payload []byte, declaration string) releasepush.Reply {
	message := &nats.Msg{Subject: subject, Data: payload}
	if declaration != "" {
		message.Header = nats.Header{releasepush.PreflightHeader: []string{declaration}}
	}
	message, err := conn.RequestMsgWithContext(ctx, message)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
}

func send(ctx context.Context, conn *nats.Conn, release releasepush.OrchRelease, declaration string) releasepush.Reply {
	payload, err := json.Marshal(release)
	must(err)
	return request(ctx, conn, releasepush.SubjectOrch, payload, declaration)
}

func ready(cmd *exec.Cmd, marker string) []string {
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
			return seen
		}
	}
	panic("process did not announce " + marker + ":\n" + strings.Join(seen[max(0, len(seen)-40):], "\n"))
}

func appendMark(path, value string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	must(err)
	_, err = fmt.Fprintln(file, value)
	must(errors.Join(err, file.Close()))
}

func marks(path string) []string {
	return strings.Fields(string(read(path)))
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if len(os.Args) == 2 && os.Args[1] == "linger" {
		<-time.NewTimer(10 * time.Minute).C
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "release" && os.Args[2] == "preflight" {
		mode, mark, _ := strings.Cut(candidateMode(), ":")
		if mark != "" {
			appendMark(mark, time.Now().Format(time.RFC3339Nano))
		}
		switch mode {
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
		case "slow":
			<-time.NewTimer(slowStep).C
		case "orphan-pass", "orphan-fail":
			helper, err := os.Executable()
			must(err)
			child := exec.Command(helper, "linger")
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			must(child.Start())
			appendMark(mark, fmt.Sprint(child.Process.Pid))
			if mode == "orphan-fail" {
				os.Exit(17)
			}
		}
		return
	}
	if len(os.Args) >= 3 {
		switch os.Args[1] {
		case "start-state":
			startState(ctx, os.Args[2], os.Args[3])
			return
		case "serve-region":
			serveRegion(ctx, os.Args[2:])
			return
		}
	}
	run(ctx, os.Args[1], os.Args[2])
}

const slowStep = 40 * time.Second
