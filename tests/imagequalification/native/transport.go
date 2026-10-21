package native

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	qualificationhost "github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
)

const maxFrame = 1 << 20

type Session = qualificationhost.Session
type SessionConfig = qualificationhost.SessionConfig

func OpenSession(ctx context.Context, cfg SessionConfig) (*Session, error) {
	return qualificationhost.OpenSession(ctx, cfg)
}

func MeasureIdentity(ctx context.Context, containerdPath, runcPath string) (Identity, error) {
	return qualificationhost.MeasureIdentity(ctx, containerdPath, runcPath)
}

type sshPeer struct{ *Session }

func connect(ctx context.Context, req Request, host Host) (peer, error) {
	session, err := OpenSession(ctx, SessionConfig{RunID: req.RunID, Host: host, User: req.SSHUser, PrivateKeyPath: req.PrivateKeyPath, WorkerPath: req.WorkerPath, WorkerSHA256: req.WorkerSHA256})
	if err != nil {
		return nil, err
	}

	return &sshPeer{session}, nil
}

func (p *sshPeer) call(ctx context.Context, c command) (response, error) {
	var result response
	if err := p.Exchange(ctx, c, &result); err != nil {
		return result, err
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, ctx.Err()
}
func (p *sshPeer) close() error { return p.Close() }
func (p *sshPeer) probeHTTP(ctx context.Context) error {
	return p.ProbeManagedHTTP(ctx)
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
