package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxFrame = 1 << 20

var runPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateRunID(value string) error {
	if !runPattern.MatchString(value) {
		return errors.New("run ID requires 1..16 lowercase alphanumeric characters, starting with a letter")
	}
	return nil
}

// SessionConfig identifies one explicitly approved disposable host and worker.
// OpenSession never discovers hosts or supplies cloud authorization.
type SessionConfig struct {
	RunID          string
	Host           Host
	User           string
	PrivateKeyPath string
	WorkerPath     string
	WorkerSHA256   string
}

// Session carries bounded worker JSON over root SSH with an exact host key pin.
// Cancellation closes the connection; create a new run rather than reusing it.
type Session struct {
	client  *ssh.Client
	session *ssh.Session
	in      io.WriteCloser
	out     *bufio.Scanner
	mu      sync.Mutex
	remote  string
}

// OpenSession uploads the exact worker and starts its fixed "serve" protocol.
// The local private key is never copied to the host.
func OpenSession(ctx context.Context, cfg SessionConfig) (*Session, error) {
	signer, err := readPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	worker, err := os.ReadFile(cfg.WorkerPath)
	if err != nil {
		return nil, err
	}
	return openSession(ctx, cfg, worker, signer)
}

func openSession(ctx context.Context, cfg SessionConfig, worker []byte, signer ssh.Signer) (_ *Session, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateRunID(cfg.RunID); err != nil {
		return nil, err
	}
	host := cfg.Host
	addressIP, addressErr := netip.ParseAddr(host.Address)
	if addressErr != nil || !addressIP.Is4() || !addressIP.IsPrivate() || !strings.HasPrefix(host.OCID, "ocid1.instance.") || cfg.User != "root" || !shaPattern.MatchString(cfg.WorkerSHA256) || digest(worker) != cfg.WorkerSHA256 {
		return nil, errors.New("native session requires a private Compute host, root and the exact worker digest")
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(host.SSHHostKey))
	if err != nil {
		return nil, fmt.Errorf("trusted host key: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("native session requires one exact trusted host key")
	}
	config := &ssh.ClientConfig{User: cfg.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(key), Timeout: 10 * time.Second}
	address := net.JoinHostPort(host.Address, "22")
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stopHandshake := context.AfterFunc(ctx, func() { raw.Close() })
	defer stopHandshake()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, channels, requests, err := ssh.NewClientConn(raw, address, config)
	if err != nil {
		raw.Close()
		return nil, err
	}
	stopHandshake()
	_ = raw.SetDeadline(time.Time{})
	client := ssh.NewClient(conn, channels, requests)
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	defer func() {
		if err != nil {
			client.Close()
		}
	}()
	upload, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	remote := "/run/ts-native-" + cfg.RunID
	// RunID has a strict alphabet. The private key is never copied to a host.
	upload.Stdin = bytes.NewReader(worker)
	var output bytes.Buffer
	upload.Stdout, upload.Stderr = &output, &output
	err = upload.Run("umask 077; test ! -e '" + remote + "' && mkdir '" + remote + "' && cat > '" + remote + "/worker' && chmod 700 '" + remote + "/worker' && sha256sum '" + remote + "/worker'")
	upload.Close()
	if err != nil {
		return nil, fmt.Errorf("upload native worker: %w", err)
	}
	if !validRemoteDigest(output.Bytes(), cfg.WorkerSHA256) {
		return nil, errors.New("remote worker digest mismatch")
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	in, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	out, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	// Runtime logs use stderr, never the protocol stream; bound them at the source.
	session.Stderr = io.Discard
	if err = session.Start("'" + remote + "/worker' serve"); err != nil {
		session.Close()
		return nil, err
	}
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), maxFrame)
	return &Session{client: client, session: session, in: in, out: scanner, remote: remote}, nil
}

// Exchange exchanges one strict newline-delimited JSON frame, at most 1 MiB.
// The caller owns its response type and any application-level error field.
func (p *Session) Exchange(ctx context.Context, input, output any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { p.client.Close() })
	defer stop()
	wire, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(wire) > maxFrame {
		return errors.New("native request too large")
	}
	if _, err = p.in.Write(append(wire, '\n')); err != nil {
		return err
	}
	if !p.out.Scan() {
		return errors.Join(io.ErrUnexpectedEOF, p.out.Err(), ctx.Err())
	}
	if err = json.Unmarshal(p.out.Bytes(), output, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	return ctx.Err()
}

// Close releases the SSH protocol and transport. Host cleanup remains the
// scenario worker's responsibility and VM deletion remains the parent's.
func (p *Session) Close() error {
	_ = p.in.Close()
	return errors.Join(p.session.Close(), p.client.Close())
}

var uploadName = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)

// UploadFile copies an explicit, digest-pinned file into this run's private
// directory. Existing files and path traversal are rejected.
func (p *Session) UploadFile(ctx context.Context, remoteBasename, path, expectedSHA256 string) error {
	if !uploadName.MatchString(remoteBasename) || strings.Contains(remoteBasename, "..") || remoteBasename == "worker" || !shaPattern.MatchString(expectedSHA256) {
		return errors.New("native upload requires a safe basename and exact digest")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return err
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != expectedSHA256 {
		return errors.New("local upload digest mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { p.client.Close() })
	defer stop()
	transfer, err := p.client.NewSession()
	if err != nil {
		return err
	}
	defer transfer.Close()
	transfer.Stdin = file
	var output bytes.Buffer
	transfer.Stdout, transfer.Stderr = &output, &output
	remote := p.remote + "/" + remoteBasename
	if err := transfer.Run("umask 077; set -C; cat > '" + remote + "' && sha256sum '" + remote + "'"); err != nil {
		return fmt.Errorf("upload native file: %w", err)
	}
	if !validRemoteDigest(output.Bytes(), expectedSHA256) {
		return errors.New("remote upload digest mismatch")
	}
	return ctx.Err()
}

func validRemoteDigest(output []byte, expected string) bool {
	fields := bytes.Fields(output)
	return len(fields) == 2 && string(fields[0]) == expected
}

func readPrivateKey(path string) (ssh.Signer, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("SSH private key must be a regular owner-only file")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	return ssh.ParsePrivateKey(wire)
}

func digest(wire []byte) string { return fmt.Sprintf("%x", sha256.Sum256(wire)) }

// ProbeHTTP checks the fixed native continuity endpoint through this pinned connection.
func (p *Session) ProbeHTTP(ctx context.Context) error {
	return probeHTTP(ctx, "http://127.0.0.1:18080/readyz", p.client.DialContext)
}

func probeHTTP(ctx context.Context, url string, dial func(context.Context, string, string) (net.Conn, error)) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: dial}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 33))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || string(body) != "ready" {
		return fmt.Errorf("native HTTP continuity: status=%d body=%q", response.StatusCode, body)
	}
	return nil
}
