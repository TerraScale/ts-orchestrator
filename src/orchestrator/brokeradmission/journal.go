package brokeradmission

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const StateKey = "broker.enrollment"
const stateSubject = "$KV.ORCH_LEADERS." + StateKey + ".state"

type WireState struct{ Wire []byte }
type Publisher struct {
	journal              *authorityjournal.Journal[WireState]
	signer               *security.CommandSignatureSigner
	verifier             *Verifier
	environment, cluster string
	epoch                uint64
	lease                string
}

func NewPublisher(config authorityjournal.Config, signer *security.CommandSignatureSigner, verifier *Verifier, environment, cluster string) (*Publisher, error) {
	if signer == nil || verifier == nil || !validToken(environment) || !validToken(cluster) {
		return nil, ErrInvalid
	}
	config.StateKey = StateKey
	j, err := authorityjournal.New(config, func() WireState { return WireState{} }, func(s WireState) error {
		if len(s.Wire) == 0 {
			return nil
		}
		_, err := verifier.Verify(s.Wire)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &Publisher{journal: j, signer: signer, verifier: verifier, environment: environment, cluster: cluster, epoch: config.AuthorityEpoch, lease: config.LeaseID}, nil
}

// Publish projects only durable published enrollments and exact completed
// retirements. Revision is the lease-fenced journal commit sequence.
func (p *Publisher) Publish(ctx context.Context, state enrollment.State) ([]byte, error) {
	d := Desired{Version: 1, Environment: p.environment, Cluster: p.cluster, AuthorityEpoch: p.epoch, LeaseID: p.lease, Members: []Member{}, Retired: []Retired{}}
	for _, r := range state.Records {
		if r.Public == nil {
			continue
		}
		if err := appendEnrollment(&d, r); err != nil {
			return nil, err
		}
	}
	for _, r := range state.Retired {
		if err := appendEnrollment(&d, r); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(d.Members, func(a, b Member) int { return strings.Compare(a.MemberID, b.MemberID) })
	slices.SortFunc(d.Retired, func(a, b Retired) int { return strings.Compare(a.Member.MemberID, b.Member.MemberID) })
	prior, err := p.journal.Read(ctx)
	if err != nil {
		return nil, err
	}
	if len(prior.Wire) > 0 {
		old, err := p.verifier.Verify(prior.Wire)
		if err != nil {
			return nil, err
		}
		d.Revision = old.Revision
		if reflect.DeepEqual(old, d) {
			return slices.Clone(prior.Wire), nil
		}
	}
	var wire []byte
	err = p.journal.TransactRevision(ctx, true, func(current *WireState, revision uint64) error {
		d.Revision = revision
		if len(current.Wire) > 0 {
			old, err := p.verifier.Verify(current.Wire)
			if err != nil {
				return err
			}
			if err = CheckAdvance(old, d); err != nil {
				return err
			}
		}
		var err error
		wire, err = Sign(d, p.signer)
		if err != nil {
			return err
		}
		current.Wire = slices.Clone(wire)
		return nil
	})
	return wire, err
}
func appendEnrollment(d *Desired, r enrollment.Record) error {
	if r.Environment != d.Environment || r.Cluster != d.Cluster {
		return ErrInvalid
	}
	m, err := FromEnrollment(r)
	if err != nil {
		return err
	}
	if r.Retirement != nil {
		d.Retired = append(d.Retired, Retired{Member: m, RemovalOperationID: r.Retirement.OperationID, ResourceID: r.Retirement.ResourceID})
	} else {
		d.Members = append(d.Members, m)
	}
	return nil
}

// ReaderPermissions cannot write leases, enrollment state or another broker's
// acknowledgement. The server binds these subjects to a dedicated NKey.
func ReaderPermissions(brokerID string) ([]string, []string, error) {
	if !validToken(brokerID) || strings.Contains(brokerID, ".") {
		return nil, nil, ErrInvalid
	}
	return []string{"$JS.API.STREAM.INFO.KV_ORCH_LEADERS", "$JS.API.STREAM.MSG.GET.KV_ORCH_LEADERS", ackSubject(brokerID)}, []string{"_INBOX.>"}, nil
}
func ackSubject(id string) string { return "$KV.ORCH_LEADERS." + StateKey + ".ack." + id }

type Ack struct {
	BrokerID string
	Revision uint64
	SHA256   string
}

func wireDigest(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }

type storedMessage struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"seq"`
	Data     []byte    `json:"data"`
	Time     time.Time `json:"time"`
}

func leaderMessage(ctx context.Context, conn *nats.Conn, subject string) (storedMessage, error) {
	if !authenticated(conn) {
		return storedMessage{}, ErrInvalid
	}
	payload, _ := json.Marshal(struct {
		Subject string `json:"last_by_subj"`
	}{subject})
	response, err := conn.RequestWithContext(ctx, "$JS.API.STREAM.MSG.GET.KV_ORCH_LEADERS", payload)
	if err != nil {
		return storedMessage{}, err
	}
	var result struct {
		Type    string              `json:"type"`
		Message storedMessage       `json:"message"`
		Error   *jetstream.APIError `json:"error"`
	}
	if len(response.Data) > 2*MaximumBytes || json.Unmarshal(response.Data, &result) != nil || result.Error != nil || result.Type != "io.nats.jetstream.api.v1.stream_msg_get_response" || result.Message.Subject != subject || result.Message.Sequence == 0 || result.Message.Time.IsZero() {
		return storedMessage{}, ErrInvalid
	}
	return result.Message, nil
}
func authenticated(conn *nats.Conn) bool {
	if conn == nil || !conn.IsConnected() || !conn.AuthRequired() || conn.Opts.Nkey == "" || conn.Opts.SignatureCB == nil || conn.Opts.AllowReconnect || conn.Opts.ReconnectBufSize >= 0 || conn.Opts.TLSConfig == nil || conn.Opts.TLSConfig.InsecureSkipVerify {
		return false
	}
	state, err := conn.TLSConnectionState()
	return err == nil && state.Version >= tls.VersionTLS13 && len(state.VerifiedChains) > 0
}
func CheckAuthority(ctx context.Context, conn *nats.Conn, d Desired) error {
	entry, err := leaderMessage(ctx, conn, "$KV.ORCH_LEADERS.authority.global")
	if err != nil {
		return err
	}
	var lease authority.RegionalAuthorityLeaseDocument
	now := time.Now().UTC()
	if json.Unmarshal(entry.Data, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != "global" || !strings.HasPrefix(lease.CandidateId, "global-controller-gru-") || lease.Epoch <= 0 || uint64(lease.Epoch) != d.AuthorityEpoch || lease.LeaseId != d.LeaseID || now.Before(lease.IssuedAt) || !now.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond)) {
		return authorityjournal.ErrFenced
	}
	return nil
}

// ReadDesired reads the committed R3 journal envelope, not a follower cache or
// an uncommitted signed proposal. Late lease commits recover its signed prior.
func ReadDesired(ctx context.Context, conn *nats.Conn, v *Verifier) ([]byte, error) {
	if !authenticated(conn) || v == nil {
		return nil, ErrInvalid
	}
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	stream, err := js.Stream(ctx, "KV_ORCH_LEADERS")
	if err != nil {
		return nil, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, err
	}
	if info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 3 || info.Config.Mirror != nil || len(info.Config.Sources) != 0 || info.Config.MaxAge != 0 {
		return nil, ErrInvalid
	}
	entry, err := leaderMessage(ctx, conn, stateSubject)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		SchemaVersion int
		Lease         authority.RegionalAuthorityLeaseDocument
		LeaseRevision uint64
		State         WireState
		PriorState    WireState
	}
	if json.Unmarshal(entry.Data, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.SchemaVersion != 1 || envelope.Lease.Validate() != nil || envelope.Lease.AuthorityId != "global" || !strings.HasPrefix(envelope.Lease.CandidateId, "global-controller-gru-") || envelope.LeaseRevision == 0 || envelope.LeaseRevision >= entry.Sequence {
		return nil, ErrInvalid
	}
	state := envelope.State
	committed := !entry.Time.Before(envelope.Lease.IssuedAt) && entry.Time.Before(envelope.Lease.IssuedAt.Add(time.Duration(envelope.Lease.DurationMilliseconds)*time.Millisecond))
	if !committed {
		state = envelope.PriorState
	}
	d, err := v.Verify(state.Wire)
	if err != nil {
		return nil, err
	}
	if d.Revision > entry.Sequence || committed && (d.AuthorityEpoch != uint64(envelope.Lease.Epoch) || d.LeaseID != envelope.Lease.LeaseId) {
		return nil, ErrInvalid
	}
	return slices.Clone(state.Wire), nil
}
func PublishAck(ctx context.Context, conn *nats.Conn, brokerID string, wire []byte, v *Verifier) error {
	if _, _, err := ReaderPermissions(brokerID); err != nil {
		return err
	}
	d, err := v.Verify(wire)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(Ack{BrokerID: brokerID, Revision: d.Revision, SHA256: wireDigest(wire)})
	if err != nil {
		return err
	}
	js, err := jetstream.New(conn)
	if err != nil {
		return err
	}
	if _, err = js.Publish(ctx, ackSubject(brokerID), payload, jetstream.WithExpectStream("KV_ORCH_LEADERS")); err != nil {
		return err
	}
	return Acknowledged(ctx, conn, []string{brokerID}, wire, v)
}
func Acknowledged(ctx context.Context, conn *nats.Conn, brokerIDs []string, wire []byte, v *Verifier) error {
	if len(brokerIDs) == 0 {
		return ErrInvalid
	}
	d, err := v.Verify(wire)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, id := range brokerIDs {
		if _, _, err := ReaderPermissions(id); err != nil || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
		entry, err := leaderMessage(ctx, conn, ackSubject(id))
		if err != nil {
			return err
		}
		var ack Ack
		if json.Unmarshal(entry.Data, &ack, json.RejectUnknownMembers(true)) != nil || ack.BrokerID != id || ack.Revision != d.Revision || ack.SHA256 != wireDigest(wire) {
			return errors.New("broker admission: required broker has not applied desired grants")
		}
	}
	return nil
}
