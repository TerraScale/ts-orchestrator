package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// Await only short replies; the authenticated operation survives a connection
// or credential expiring. Repeated requests poll the same verified identity.
func awaitApp(ctx context.Context, release AppRelease, conn *nats.Conn, mint func(context.Context) (string, error), dial func(string) (*nats.Conn, error), poll time.Duration, progress func(Reply)) (Reply, error) {
	return awaitOperation(ctx, release.Token, conn, mint, dial, poll, progress, SubjectApp, func(token string) ([]byte, error) {
		release.Token = token
		return json.Marshal(release)
	})
}

// AwaitMesh polls the same mesh operation with renewable workflow credentials.
func AwaitMesh(ctx context.Context, region Region, subject string, mesh MeshRequest) (Reply, error) {
	return awaitOperation(ctx, mesh.Token, nil, MintToken, func(token string) (*nats.Conn, error) {
		return Dial(region, token, nats.Name("ts-orch release mesh-check"))
	}, 5*time.Second, func(Reply) {}, subject, func(token string) ([]byte, error) {
		mesh.Token = token
		return json.Marshal(mesh)
	})
}

const deadlineGrace = 20 * time.Second

func awaitOperation(ctx context.Context, token string, conn *nats.Conn, mint func(context.Context) (string, error), dial func(string) (*nats.Conn, error), poll time.Duration, progress func(Reply), subject string, encode func(string) ([]byte, error)) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, HandlerWait+10*time.Second)
	defer cancel()
	var deadline time.Time
	claims, err := appTokenClaims(token)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return Reply{}, err
	}
	identity := func(c Claims) [8]string {
		return [8]string{c.Repository, c.RepositoryOwner, c.RunID, c.RunAttempt, c.SHA, c.Ref, c.JobWorkflowRef, c.WorkflowRef}
	}
	var lastErr error
	for {
		if conn == nil {
			if token == "" || !time.Now().Add(30*time.Second).Before(time.Unix(claims.Expires, 0)) {
				nextToken, err := mint(ctx)
				if err != nil {
					return Reply{}, err
				}
				next, err := appTokenClaims(nextToken)
				if err != nil || identity(next) != identity(claims) {
					return Reply{}, errors.New("renewed release credential changed workflow identity")
				}
				token, claims = nextToken, next
			}
			conn, err = dial(token)
		}
		if err == nil {
			payload, encodeErr := encode(token)
			if encodeErr != nil {
				conn.Close()
				return Reply{}, encodeErr
			}
			reply, requestErr := request(ctx, conn, subject, payload, 15*time.Second)
			conn.Close()
			conn, err = nil, requestErr
			if err == nil {
				progress(reply)
			}
			if err == nil && reply.State != "accepted" {
				return reply, nil
			}
			if err == nil && !reply.Deadline.IsZero() && deadline.IsZero() {
				deadline = reply.Deadline
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, deadline.Add(deadlineGrace))
				defer stop()
			}
		}
		if err != nil {
			lastErr, token = err, "" // A dropped connection gets a fresh credential.
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			if !deadline.IsZero() && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return Reply{}, errors.Join(fmt.Errorf("ts-orch did not report the outcome by its deadline %s", deadline.UTC().Format(time.RFC3339)), lastErr)
			}
			return Reply{}, errors.Join(ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

// Claims decoded here control renewal and identity continuity only. The release
// listener verifies the signature, authorization and expiry on every request.
func appTokenClaims(token string) (claims Claims, err error) {
	parts := strings.Split(token, ".")
	if len(token) > maxTokenSize || len(parts) != 3 || decodeSegment(parts[1], &claims) != nil || claims.Expires == 0 || !runID.MatchString(claims.RunID) {
		err = errors.New("invalid release credential")
	}
	return claims, err
}
