package natscell

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// JetStream metadata subjects the narrowly scoped membership user may call.
// They are system-account APIs; the claim-update system user cannot use them.
const (
	MembershipServerRemoveSubject = "$JS.API.SERVER.REMOVE"
	MembershipMetaStepdownSubject = "$JS.API.META.LEADER.STEPDOWN"
)

// MetaReplica is one JetStream metadata peer as seen by the local server.
type MetaReplica struct {
	Name    string
	Current bool
	Offline bool
	Pending bool
	Active  time.Duration
	Lag     uint64
}

// metaReplicas converts a Jsz metadata replica list into name-sorted
// MetaReplica values. Both the read-only cluster health observation and the
// controller slot membership reconciler read peers through it.
func metaReplicas(replicas []*server.PeerInfo) []MetaReplica {
	var out []MetaReplica
	for _, peer := range replicas {
		if peer == nil || peer.Name == "" {
			continue
		}
		out = append(out, MetaReplica{Name: peer.Name, Current: peer.Current,
			Offline: peer.Offline, Pending: peer.Pending, Active: peer.Active, Lag: peer.Lag})
	}
	slices.SortFunc(out, func(a, b MetaReplica) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// MetaView is the local server's JetStream metadata group view.
type MetaView struct {
	Self     string
	Leader   string
	Size     int
	Replicas []MetaReplica
}

// Meta reads the local embedded server's JetStream metadata view. A follower
// can report stale peer state; callers must apply a grace before acting.
func (r *Runtime) Meta() (MetaView, error) {
	if r == nil || r.server == nil {
		return MetaView{}, errors.New("embedded regional NATS server is unavailable")
	}
	if !r.server.Running() {
		return MetaView{}, errors.New("embedded regional NATS server is not running")
	}
	info, err := r.server.Jsz(nil)
	if err != nil {
		return MetaView{}, fmt.Errorf("read JetStream metadata: %w", err)
	}
	if info.Meta == nil {
		return MetaView{}, errors.New("JetStream metadata group is not clustered")
	}
	view := MetaView{Self: r.server.Name(), Leader: info.Meta.Leader, Size: info.Meta.Size}
	view.Replicas = metaReplicas(info.Meta.Replicas)
	return view, nil
}

// ValidateMembershipCredentials requires a system-account user that may only
// remove a JetStream metadata peer, step the metadata leader down and receive
// replies on its private inbox. It is used only for decommission and step-down
// and is deliberately separate from the claim-update system user.
func ValidateMembershipCredentials(path, cell, systemAccount string) error {
	if !cellName.MatchString(cell) || systemAccount == "" {
		return errors.New("membership credential cell or system account is invalid")
	}
	claim, public, err := credentialUser(path)
	if err != nil {
		return fmt.Errorf("membership credentials: %w", err)
	}
	publishes := slices.Clone([]string(claim.Pub.Allow))
	slices.Sort(publishes)
	if credentialAccount(claim) != systemAccount ||
		!slices.Equal(publishes, []string{MembershipMetaStepdownSubject, MembershipServerRemoveSubject}) ||
		len(claim.Pub.Deny) != 0 || len(claim.Sub.Allow) != 1 ||
		claim.Sub.Allow[0] != inboxPrefix(cell, public)+".>" || len(claim.Sub.Deny) != 0 ||
		claim.Resp != nil {
		return errors.New("membership credentials must have only server-remove, metadata step-down and private reply grants")
	}
	return nil
}

// MembershipAdmin is an in-process system-account connection limited to the
// JetStream metadata peer-remove and leader step-down APIs.
type MembershipAdmin struct {
	conn  *nats.Conn
	inbox string
}

// OpenMembershipAdmin connects in-process with path after validating that it
// holds only the membership grants for this broker's pinned system account.
func (r *Runtime) OpenMembershipAdmin(path string) (*MembershipAdmin, error) {
	if r == nil || r.server == nil || r.resolver == nil || r.operator == nil {
		return nil, errors.New("production membership administration is unavailable")
	}
	if err := ValidateMembershipCredentials(path, r.cell, r.resolver.system); err != nil {
		return nil, err
	}
	_, public, err := credentialUser(path)
	if err != nil {
		return nil, err
	}
	inbox := inboxPrefix(r.cell, public)
	options := []nats.Option{nats.UserCredentials(path), nats.InProcessServer(r.server),
		nats.CustomInboxPrefix(inbox), nats.Name("ts-orch-membership"), nats.NoReconnect(), nats.ErrorHandler(ErrorHandler)}
	conn, err := nats.Connect(r.server.ClientURL(), options...)
	if err != nil {
		return nil, fmt.Errorf("connect membership system user: %w", err)
	}
	return &MembershipAdmin{conn: conn, inbox: inbox}, nil
}

func (a *MembershipAdmin) Close() {
	if a != nil && a.conn != nil {
		a.conn.Close()
	}
}

// RemovePeer removes a decommissioned server from the JetStream metadata
// group. A replaced slot keeps its server name and must not be removed.
func (a *MembershipAdmin) RemovePeer(ctx context.Context, serverName string) error {
	if serverName == "" || len(serverName) > 128 {
		return errors.New("membership peer name is invalid")
	}
	body, err := json.Marshal(struct {
		Server string `json:"peer"`
	}{Server: serverName})
	if err != nil {
		return err
	}
	return a.request(ctx, MembershipServerRemoveSubject, body)
}

// StepDownMetaLeader asks the current JetStream metadata leader to resign.
func (a *MembershipAdmin) StepDownMetaLeader(ctx context.Context) error {
	return a.request(ctx, MembershipMetaStepdownSubject, nil)
}

func (a *MembershipAdmin) request(ctx context.Context, subject string, body []byte) error {
	if a == nil || a.conn == nil {
		return errors.New("membership administration is closed")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	message, err := a.conn.RequestWithContext(requestCtx, subject, body)
	if err != nil {
		return fmt.Errorf("request %s: %w", subject, err)
	}
	return membershipAPIError(subject, message.Data)
}

func membershipAPIError(subject string, data []byte) error {
	var response struct {
		Error *struct {
			Code        int    `json:"code"`
			ErrCode     uint16 `json:"err_code"`
			Description string `json:"description"`
		} `json:"error"`
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("decode %s response: %w", subject, err)
	}
	if response.Error != nil {
		return fmt.Errorf("%s: %s (code %d, err_code %d)", subject, response.Error.Description,
			response.Error.Code, response.Error.ErrCode)
	}
	if !response.Success {
		return fmt.Errorf("%s did not report success", subject)
	}
	return nil
}
