package rootsecret

import (
	"bytes"
	"crypto/tls"
	"encoding/json/v2"
	"net"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// NetBirdJournalMaterial adds a separate journal identity to the same immutable
// broker CURRENT. The embedded readonly credential bytes retain their expiry.
type NetBirdJournalMaterial struct {
	NetBirdBrokerMaterial
	JournalCredentials []byte `json:"journal_credentials"`
	PurposeSHA256      string `json:"purpose_sha256"`
	UnderlaySHA256     string `json:"underlay_sha256"`
	WriterInstance     string `json:"writer_instance"`
	WriterVNIC         string `json:"writer_vnic"`
	ManagerVNIC        string `json:"manager_vnic"`
}

func (NetBirdJournalMaterial) String() string     { return "NetBird journal material [redacted]" }
func (m NetBirdJournalMaterial) GoString() string { return m.String() }

func (m NetBirdJournalMaterial) Encode() ([]byte, error) {
	if m.Schema != 2 || len(m.Endpoints) != 0 {
		return nil, ErrDelivery
	}
	wire, err := json.Marshal(m)
	if err != nil || len(wire) == 0 || len(wire) > NetBirdBrokerMaterialLimit {
		clear(wire)
		return nil, ErrDelivery
	}
	return wire, nil
}

func DecodeNetBirdJournalMaterial(wire []byte) (NetBirdJournalMaterial, error) {
	var m NetBirdJournalMaterial
	if len(wire) == 0 || len(wire) > NetBirdBrokerMaterialLimit || json.Unmarshal(wire, &m, json.RejectUnknownMembers(true)) != nil ||
		m.Schema != 2 || len(m.Endpoints) != 0 {
		return NetBirdJournalMaterial{}, ErrDelivery
	}
	return m, nil
}

// NewNetBirdJournalMaterial preserves the authenticated readonly credential and
// TLS bytes, including during a separately authorized exact-version migration.
func NewNetBirdJournalMaterial(s NetBirdJournalSource, readonly NetBirdBrokerMaterial, journalCredentials []byte, now time.Time) (NetBirdJournalMaterial, error) {
	if readonly.Schema != 1 {
		return NetBirdJournalMaterial{}, ErrDelivery
	}
	readonly.Schema = 2
	readonly.Endpoints = nil
	readonly.Credentials = bytes.Clone(readonly.Credentials)
	readonly.CA, readonly.Operator, readonly.Account = bytes.Clone(readonly.CA), bytes.Clone(readonly.Operator), bytes.Clone(readonly.Account)
	readonly.Certificate, readonly.Key = bytes.Clone(readonly.Certificate), bytes.Clone(readonly.Key)
	m := NetBirdJournalMaterial{NetBirdBrokerMaterial: readonly, JournalCredentials: bytes.Clone(journalCredentials), PurposeSHA256: s.purpose.Digest(),
		UnderlaySHA256: s.underlay.Digest(), WriterInstance: s.underlay.WriterInstanceID(), WriterVNIC: s.underlay.WriterVNICID(), ManagerVNIC: s.underlay.ManagerVNICID()}
	if _, _, err := CheckNetBirdJournalMaterial(m, s, now); err != nil {
		clearNetBirdJournalMaterial(m)
		return NetBirdJournalMaterial{}, err
	}
	return m, nil
}

func clearNetBirdJournalMaterial(m NetBirdJournalMaterial) {
	clear(m.JournalCredentials)
	clear(m.Credentials)
	clear(m.Key)
}

// CheckNetBirdJournalMaterial returns authenticated claims and client TLS only.
// Callers still revalidate opaque source and exact CURRENT around every effect.
func CheckNetBirdJournalMaterial(m NetBirdJournalMaterial, s NetBirdJournalSource, now time.Time) (*tls.Config, bootstrapmaterial.NetBirdJournalCredential, error) {
	var empty bootstrapmaterial.NetBirdJournalCredential
	if m.Schema != 2 || len(m.Endpoints) != 0 || !s.purpose.IsVerified() || !s.underlay.IsVerified() ||
		m.PurposeSHA256 != s.purpose.Digest() || m.UnderlaySHA256 == "" || m.UnderlaySHA256 != s.underlay.Digest() ||
		m.WriterInstance != s.underlay.WriterInstanceID() || m.WriterVNIC != s.underlay.WriterVNICID() ||
		m.ManagerInstance != s.underlay.ManagerInstanceID() || m.ManagerVNIC != s.underlay.ManagerVNICID() || !now.Before(s.expires) {
		return nil, empty, ErrDelivery
	}
	// Reuse the exact readonly verifier; runtime endpoints come from the source.
	readonly := m.NetBirdBrokerMaterial
	readonly.Schema, readonly.Endpoints = 1, s.readonly.endpoints
	config, readerPublic, err := CheckNetBirdBrokerMaterial(readonly, s.readonly, s.recipient, now)
	if err != nil {
		return nil, empty, ErrDelivery
	}
	deadline := minDeadline(m.ExpiresAt, minDeadline(s.expires, minDeadline(s.purpose.ExpiresAt(), s.underlay.ExpiresAt())))
	purpose := s.purpose.Purpose()
	binding := bootstrapmaterial.NetBirdJournalCredentialBinding{PurposeSHA256: s.purpose.Digest(), GrantSHA256: s.purpose.GrantDigest(),
		TemplateSHA256: s.purpose.TemplateDigest(), SourceSHA256: s.public.startup.SourceSHA256(), ManagerSlotID: purpose.Manager.SlotID, WriterSlotID: purpose.Writer.SlotID}
	raw, err := jwt.ParseDecoratedJWT(m.JournalCredentials)
	if err != nil {
		return nil, empty, ErrDelivery
	}
	credential, err := bootstrapmaterial.VerifyNetBirdJournalCredential(raw, s.public.record.Public.CellAccountNKey,
		s.public.record.Public.ControllerAccountSignerNKey, binding, deadline, now)
	if err != nil || credential.Subject == readerPublic {
		return nil, empty, ErrDelivery
	}
	pair, err := nkeys.ParseDecoratedUserNKey(m.JournalCredentials)
	if err != nil {
		return nil, empty, ErrDelivery
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil || public != credential.Subject {
		return nil, empty, ErrDelivery
	}
	return config, credential, nil
}

// CheckNetBirdJournalManagerPeer accepts only the actual native manager's mTLS
// leaf and private source IP. The HTTPS handler supplies its real connection data.
func CheckNetBirdJournalManagerPeer(state *tls.ConnectionState, remoteAddress string, m NetBirdJournalMaterial, s NetBirdJournalSource, now time.Time) error {
	config, _, err := CheckNetBirdJournalMaterial(m, s, now)
	if err != nil || state == nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return ErrDelivery
	}
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil || host != s.purpose.Purpose().Underlay.ManagerPrivateIP {
		return ErrDelivery
	}
	certificate := config.Certificates[0]
	if len(certificate.Certificate) != 2 || !bytes.Equal(state.PeerCertificates[0].Raw, certificate.Certificate[0]) {
		return ErrDelivery
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) >= 2 && bytes.Equal(chain[0].Raw, certificate.Certificate[0]) && bytes.Equal(chain[1].Raw, certificate.Certificate[1]) {
			return nil
		}
	}
	return ErrDelivery
}
