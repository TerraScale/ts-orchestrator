package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// Await only short replies; the authenticated operation survives a connection
// or credential expiring. Repeated requests poll the same verified identity.
func awaitApp(ctx context.Context, release AppRelease, conn *nats.Conn, mint func(context.Context) (string, error), dial func(string) (*nats.Conn, error), poll time.Duration) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, HandlerWait+10*time.Second)
	defer cancel()
	claims, err := appTokenClaims(release.Token)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return Reply{}, err
	}
	identity := func(c Claims) [7]string {
		return [7]string{c.Repository, c.RepositoryOwner, c.RunID, c.SHA, c.Ref, c.JobWorkflowRef, c.WorkflowRef}
	}
	var lastErr error
	for {
		if conn == nil {
			if release.Token == "" || !time.Now().Add(30*time.Second).Before(time.Unix(claims.Expires, 0)) {
				token, err := mint(ctx)
				if err != nil {
					return Reply{}, err
				}
				next, err := appTokenClaims(token)
				if err != nil || identity(next) != identity(claims) {
					return Reply{}, errors.New("renewed release credential changed workflow identity")
				}
				release.Token, claims = token, next
			}
			conn, err = dial(release.Token)
		}
		if err == nil {
			payload, encodeErr := json.Marshal(release)
			if encodeErr != nil {
				conn.Close()
				return Reply{}, encodeErr
			}
			reply, requestErr := request(ctx, conn, SubjectApp, payload, 15*time.Second)
			conn.Close()
			conn, err = nil, requestErr
			if err == nil && reply.State != "accepted" {
				return reply, nil
			}
		}
		if err != nil {
			lastErr, release.Token = err, "" // A dropped connection gets a fresh credential.
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
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
