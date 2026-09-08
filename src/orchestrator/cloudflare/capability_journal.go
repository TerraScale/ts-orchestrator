package cloudflare

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const maximumCapabilityReceiptBytes = 16 << 10

var ErrCapabilityJournalUnavailable = errors.New("cloudflare: capability journal unavailable")
var ErrCapabilityJournalConflict = errors.New("cloudflare: capability journal revision conflict")

// CapabilityReceipt contains only provider identities and secret-free key metadata.
type CapabilityReceipt struct {
	Generation            uint64
	Current               security.CapabilityKeyState
	Previous              security.CapabilityKeyState
	OriginCurrent         security.CapabilityKeyState
	OriginPrevious        security.CapabilityKeyState
	Phase                 string
	Digest                string
	TemplateDigest        string
	OperationID           string
	RevocationRevision    uint64
	Revocations           []CapabilityRevocation
}

// CapabilityJournal does not grant authority; callers fence their provider effects.
type CapabilityJournal interface {
	Load(context.Context) (CapabilityReceipt, uint64, error)
	Save(context.Context, CapabilityReceipt, uint64) error
}

type NATSCapabilityJournalConfig struct {
	Connection *nats.Conn
	Bucket     string
	Key        string
}

type NATSCapabilityJournal struct {
	connection *nats.Conn
	js         jetstream.JetStream
	bucket     string
	key        string
}

var _ CapabilityJournal = (*NATSCapabilityJournal)(nil)

// NewNATSCapabilityJournal binds an existing file-backed, nonexpiring R3 KV
// bucket. It never creates infrastructure or supplies deployment defaults.
func NewNATSCapabilityJournal(ctx context.Context, config NATSCapabilityJournalConfig) (*NATSCapabilityJournal, error) {
	if ctx == nil || config.Connection == nil || !journalName(config.Bucket, false) || !journalName(config.Key, true) {
		return nil, ErrCapabilityJournalUnavailable
	}
	js, err := jetstream.New(config.Connection)
	if err != nil {
		return nil, ErrCapabilityJournalUnavailable
	}
	journal := &NATSCapabilityJournal{connection: config.Connection, js: js, bucket: config.Bucket, key: config.Key}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := journal.validateStream(bounded); err != nil {
		return nil, err
	}
	return journal, nil
}

func journalName(value string, dots bool) bool {
	if len(value) == 0 || len(value) > 128 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || dots && c == '.') {
			return false
		}
	}
	return !strings.Contains(value, "..")
}

func (j *NATSCapabilityJournal) validateStream(ctx context.Context) error {
	info, err := j.js.Stream(ctx, "KV_"+j.bucket)
	if err != nil {
		return ErrCapabilityJournalUnavailable
	}
	c := info.CachedInfo().Config
	if c.Name != "KV_"+j.bucket || c.Storage != jetstream.FileStorage || c.Replicas != 3 || c.MaxAge != 0 || c.AllowMsgTTL || c.SubjectDeleteMarkerTTL != 0 || c.Mirror != nil || len(c.Sources) != 0 || c.Retention != jetstream.LimitsPolicy || c.Discard != jetstream.DiscardNew || c.MaxMsgs != -1 || c.MaxMsgsPerSubject < 1 || len(c.Subjects) != 1 || c.Subjects[0] != "$KV."+j.bucket+".>" {
		return ErrCapabilityJournalUnavailable
	}
	return nil
}

func (j *NATSCapabilityJournal) Load(ctx context.Context) (CapabilityReceipt, uint64, error) {
	if j == nil || ctx == nil {
		return CapabilityReceipt{}, 0, ErrCapabilityJournalUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := j.validateStream(bounded); err != nil {
		return CapabilityReceipt{}, 0, err
	}
	subject := "$KV." + j.bucket + "." + j.key
	payload, _ := json.Marshal(struct {
		Last string `json:"last_by_subj"`
	}{subject})
	// The stream helper chooses DIRECT.GET when AllowDirect is set on a KV
	// bucket. Explicit MSG.GET always routes this receipt read to the leader.
	response, err := j.connection.RequestWithContext(bounded, "$JS.API.STREAM.MSG.GET.KV_"+j.bucket, payload)
	if err != nil || response == nil || len(response.Data) > maximumCapabilityReceiptBytes*2 {
		return CapabilityReceipt{}, 0, ErrCapabilityJournalUnavailable
	}
	var result struct {
		Message struct {
			Subject  string `json:"subject"`
			Sequence uint64 `json:"seq"`
			Data     []byte `json:"data"`
			Headers  []byte `json:"hdrs"`
		} `json:"message"`
		Error *jetstream.APIError `json:"error"`
	}
	if json.Unmarshal(response.Data, &result) != nil {
		return CapabilityReceipt{}, 0, ErrCapabilityJournalUnavailable
	}
	if result.Error != nil {
		if result.Error.ErrorCode == jetstream.JSErrCodeMessageNotFound {
			return CapabilityReceipt{}, 0, nil
		}
		return CapabilityReceipt{}, 0, ErrCapabilityJournalUnavailable
	}
	m := result.Message
	if m.Subject != subject || m.Sequence == 0 || len(m.Headers) > 4096 || strings.Contains(strings.ToLower(string(m.Headers)), "kv-operation:") {
		return CapabilityReceipt{}, 0, ErrCapabilityJournalUnavailable
	}
	receipt, err := decodeCapabilityReceipt(m.Data)
	return receipt, m.Sequence, err
}

func (j *NATSCapabilityJournal) Save(ctx context.Context, receipt CapabilityReceipt, revision uint64) error {
	if j == nil || ctx == nil {
		return ErrCapabilityJournalUnavailable
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return ErrCapabilityJournalUnavailable
	}
	if _, err := decodeCapabilityReceipt(raw); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := j.validateStream(bounded); err != nil {
		return err
	}
	// Publish with an expected subject revision, including zero for creation.
	// Unlike KV.Create this cannot resurrect a deleted key after a stale read.
	_, err = j.js.Publish(bounded, "$KV."+j.bucket+"."+j.key, raw, jetstream.WithExpectStream("KV_"+j.bucket), jetstream.WithExpectLastSequencePerSubject(revision))
	if err != nil {
		if api, ok := errors.AsType[*jetstream.APIError](err); ok && (api.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || api.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
			return ErrCapabilityJournalConflict
		}
		return ErrCapabilityJournalUnavailable
	}
	return nil
}

func decodeCapabilityReceipt(raw []byte) (CapabilityReceipt, error) {
	var receipt CapabilityReceipt
	if len(raw) == 0 || len(raw) > maximumCapabilityReceiptBytes || json.Unmarshal(raw, &receipt, json.RejectUnknownMembers(true)) != nil {
		return CapabilityReceipt{}, ErrCapabilityJournalUnavailable
	}
	if receipt.Generation == 0 || receipt.Current.Version != receipt.Generation || (security.CapabilityKeyRing{Current: receipt.Current, Previous: receipt.Previous}).Validate() != nil {
		return CapabilityReceipt{}, ErrCapabilityJournalUnavailable
	}
	for _, value := range []string{receipt.Phase, receipt.Digest, receipt.OperationID, receipt.Current.ID, receipt.Current.Reference} {
		if len(value) == 0 || len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00") {
			return CapabilityReceipt{}, ErrCapabilityJournalUnavailable
		}
	}
	if len(receipt.Previous.ID) > 1024 || len(receipt.Previous.Reference) > 1024 {
		return CapabilityReceipt{}, ErrCapabilityJournalUnavailable
	}
	if !validCapabilityRevocations(receipt.Revocations) {
		return CapabilityReceipt{}, ErrCapabilityJournalUnavailable
	}
	return receipt, nil
}
