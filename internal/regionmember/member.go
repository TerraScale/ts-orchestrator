package regionmember

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const (
	actionList    = "ls"
	actionPromote = "promote"
	listWait      = 10 * time.Second
	promoteWait   = 2 * time.Minute
	reconnect     = 10 * time.Second
	maxMessage    = 256 << 10
)

type request struct {
	Token string `json:"token,omitempty"`
}

type Reply struct {
	Region    string                  `json:"region"`
	Leader    string                  `json:"leader"`
	Members   swarmruntime.MemberList `json:"members"`
	Promotion *swarmruntime.Promotion `json:"promotion,omitempty"`
	Error     string                  `json:"error,omitempty"`
}

func Serve(ctx context.Context, state string, node *swarmruntime.Node, verifier *releasepush.Verifier) {
	tick := time.NewTicker(reconnect)
	defer tick.Stop()
	var conn *nats.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	for {
		if conn == nil || conn.IsClosed() {
			if conn, _ = mesh.Connect(state); conn != nil {
				if err := serve(ctx, conn, node, verifier); err != nil {
					slog.WarnContext(ctx, "region member responder failed", "error", err)
					conn.Close()
					conn = nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func serve(ctx context.Context, conn *nats.Conn, node *swarmruntime.Node, verifier *releasepush.Verifier) error {
	region := mesh.ConnRegion(conn)
	if region == "" {
		return errors.New("mesh server has no region identity")
	}
	for _, action := range []string{actionList, actionPromote} {
		if _, err := conn.Subscribe(protocol.MeshMemberSubject(region, action), func(m *nats.Msg) {
			go answer(ctx, node, verifier, region, action, m)
		}); err != nil {
			return err
		}
	}
	return conn.Flush()
}

func answer(ctx context.Context, node *swarmruntime.Node, verifier *releasepush.Verifier, region, action string, m *nats.Msg) {
	var asked request
	if err := protocol.DecodeStrict(m.Data, &asked, maxMessage); err != nil {
		return
	}
	if _, err := node.MemberView(); errors.Is(err, swarmruntime.ErrNotRegionLeader) {
		return
	}
	leader, _ := os.Hostname()
	reply := Reply{Region: region, Leader: leader}
	if action == actionPromote {
		reply.Promotion, reply.Error = promote(ctx, node, verifier, region, asked.Token)
	}
	members, err := node.MemberView()
	reply.Members = members
	if err != nil {
		reply.Error = strings.TrimPrefix(reply.Error+"; "+err.Error(), "; ")
	}
	data, err := protocol.EncodeJSON(reply)
	if err == nil {
		err = m.Respond(data)
	}
	if err != nil {
		slog.WarnContext(ctx, "region member reply failed", "region", region, "error", err)
	}
}

func promote(ctx context.Context, node *swarmruntime.Node, verifier *releasepush.Verifier, region, token string) (*swarmruntime.Promotion, string) {
	verifyCtx, cancel := context.WithTimeout(ctx, listWait)
	claims, err := verifier.VerifyPromote(verifyCtx, token, region)
	cancel()
	if err != nil {
		slog.WarnContext(ctx, "operator promotion refused", "region", region, "error", err)
		return nil, "promotion refused: " + err.Error()
	}
	promoteCtx, cancel := context.WithTimeout(ctx, promoteWait-10*time.Second)
	defer cancel()
	promotion, err := node.PromoteManager(promoteCtx, claims.ID)
	slog.InfoContext(ctx, "operator promotion", "region", region, "run", claims.RunID, "attempt", claims.RunAttempt, "jti", claims.ID,
		"promoted", promotion.Hostname, "voters", promotion.Voters, "error", err)
	if err != nil {
		return nil, err.Error()
	}
	return &promotion, ""
}

func List(ctx context.Context, conn *nats.Conn, region string) (Reply, error) {
	return ask(ctx, conn, region, actionList, request{}, listWait)
}

func Promote(ctx context.Context, conn *nats.Conn, region, token string) (Reply, error) {
	return ask(ctx, conn, region, actionPromote, request{Token: token}, promoteWait)
}

func ask(ctx context.Context, conn *nats.Conn, region, action string, asked request, wait time.Duration) (Reply, error) {
	if regions := mesh.ConnRegions(conn); !slices.Contains(regions, region) {
		return Reply{}, fmt.Errorf("unknown region %q; the mesh has %s", region, strings.Join(regions, ", "))
	}
	data, err := protocol.EncodeJSON(asked)
	if err != nil {
		return Reply{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	response, err := conn.RequestWithContext(ctx, protocol.MeshMemberSubject(region, action), data)
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		return Reply{}, fmt.Errorf("no manager of %s is on the mesh", region)
	case errors.Is(err, context.DeadlineExceeded):
		return Reply{}, fmt.Errorf("%s's Raft leader did not answer within %s", region, wait)
	case err != nil:
		return Reply{}, err
	}
	var reply Reply
	if err := protocol.DecodeStrict(response.Data, &reply, maxMessage); err != nil {
		return Reply{}, err
	}
	if reply.Error != "" {
		return reply, errors.New(reply.Error)
	}
	return reply, nil
}

type Relay struct {
	Region   string
	State    string
	Verifier *releasepush.Verifier
}

func (r Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Region == "" {
		http.Error(w, "this host serves no region", http.StatusServiceUnavailable)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, maxMessage))
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if _, err := r.Verifier.VerifyPromote(req.Context(), token, r.Region); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := mesh.ConnectPromoter(r.State)
	if err != nil {
		http.Error(w, "mesh unavailable", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()
	reply, err := Promote(req.Context(), conn, r.Region, token)
	status := http.StatusOK
	if err != nil {
		status = http.StatusConflict
		if reply.Region == "" {
			reply.Error, status = err.Error(), http.StatusBadGateway
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, reply)
}
