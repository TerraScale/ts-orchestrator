package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxFrame = 1 << 20

type sshPeer struct {
	client  *ssh.Client
	session *ssh.Session
	in      io.WriteCloser
	out     *bufio.Scanner
	mu      sync.Mutex
}

func connect(ctx context.Context, req Request, host Host, worker []byte, signer ssh.Signer) (_ peer, err error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(host.SSHHostKey))
	if err != nil {
		return nil, fmt.Errorf("trusted host key: %w", err)
	}
	config := &ssh.ClientConfig{User: req.SSHUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(key), Timeout: 10 * time.Second}
	address := net.JoinHostPort(host.Address, "22")
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, channels, requests, err := ssh.NewClientConn(raw, address, config)
	if err != nil {
		raw.Close()
		return nil, err
	}
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
	remote := "/run/ts-native-" + req.RunID
	// RunID has a strict alphabet. The private key is never copied to a host.
	upload.Stdin = bytes.NewReader(worker)
	var output bytes.Buffer
	upload.Stdout, upload.Stderr = &output, &output
	err = upload.Run("umask 077; test ! -e '" + remote + "' && mkdir '" + remote + "' && cat > '" + remote + "/worker' && chmod 700 '" + remote + "/worker' && sha256sum '" + remote + "/worker'")
	upload.Close()
	if err != nil {
		return nil, fmt.Errorf("upload native worker: %w", err)
	}
	if !bytes.HasPrefix(output.Bytes(), []byte(req.WorkerSHA256+" ")) {
		return nil, errors.New("remote worker digest mismatch")
	}
	archive, err := os.Open(req.WorkloadArchivePath)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	transfer, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	transfer.Stdin = archive
	err = transfer.Run("umask 077; cat > '" + remote + "/workload.oci'")
	transfer.Close()
	if err != nil {
		return nil, fmt.Errorf("transfer workload archive: %w", err)
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
	return &sshPeer{client: client, session: session, in: in, out: scanner}, nil
}

func (p *sshPeer) call(ctx context.Context, c command) (response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { p.client.Close() })
	defer stop()
	wire, err := json.Marshal(c)
	if err != nil {
		return response{}, err
	}
	if len(wire) > maxFrame {
		return response{}, errors.New("native request too large")
	}
	if _, err = p.in.Write(append(wire, '\n')); err != nil {
		return response{}, err
	}
	var result response
	if !p.out.Scan() {
		return result, errors.Join(io.ErrUnexpectedEOF, p.out.Err())
	}
	if err = json.Unmarshal(p.out.Bytes(), &result); err != nil {
		return result, err
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, ctx.Err()
}

func (p *sshPeer) close() error {
	_ = p.in.Close()
	return errors.Join(p.session.Close(), p.client.Close())
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

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (p *sshPeer) probeHTTP(ctx context.Context) error {
	return probeHTTP(ctx, "http://127.0.0.1:18080/readyz", p.client.DialContext)
}
