// Package initialgrant verifies an initial control launch under the existing
// owner-signed host grant. It does not create signing authority or control stores.
package initialgrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
)

const Arguments = "initial-gru-r1 --config @config"
const Mode = "initial-gru-r1"
const MaximumConfigBytes = 64 << 10

type TLSFiles struct {
	CAFile            string `json:"caFile"`
	CASHA256          string `json:"caSha256"`
	CertificateFile   string `json:"certificateFile"`
	CertificateSHA256 string `json:"certificateSha256"`
	KeyFile           string `json:"keyFile"`
}
type Connection struct {
	NKeySeedFile string   `json:"nkeySeedFile"`
	PublicNKey   string   `json:"publicNkey"`
	TLS          TLSFiles `json:"tls"`
}
type Store struct {
	Account     string      `json:"account"`
	Provisioner *Connection `json:"provisioner"`
	Runtime     Connection  `json:"runtime"`
}

// PreliminaryCaptureConfig admits a source-owned local worker. Its credentials
// are privileged broker credentials, never an externally usable read-only role.
type PreliminaryCaptureConfig struct {
	RequestFile      string                        `json:"requestFile"`
	OutputDir        string                        `json:"outputDir"`
	MaxSnapshotBytes int64                         `json:"maxSnapshotBytes"`
	MaxTotalBytes    int64                         `json:"maxTotalBytes"`
	Regional         Connection                    `json:"regional"`
	Global           Connection                    `json:"global"`
	Publication      *PreliminaryPublicationConfig `json:"publication,omitempty"`
}

// PreliminaryPublicationConfig admits only source-owned publication under a
// separately signed finite transfer request. OCI identities are instance-bound;
// no owner or OCI API private key is delivered to this worker.
type PreliminaryPublicationConfig struct {
	RequestFile string             `json:"requestFile"`
	StateDir    string             `json:"stateDir"`
	Journal     Connection         `json:"journal"`
	Identity    ociinstance.Config `json:"identity"`
}
type Broker struct {
	Configuration      string   `json:"configuration"`
	ServerName         string   `json:"serverName"`
	StoreDir           string   `json:"storeDir"`
	Endpoint           string   `json:"endpoint"`
	StorageBudgetBytes int64    `json:"storageBudgetBytes"`
	TLS                TLSFiles `json:"tls"`
}
type Membership struct {
	SigningKeyFile string `json:"signingKeyFile"`
	PublicKey      string `json:"publicKey"`
	PinsFile       string `json:"pinsFile"`
	PinsSHA256     string `json:"pinsSha256"`
}
type Peer struct {
	AuthorityReaderPublicNKey string `json:"authorityReaderPublicNkey"`
	Instance                  string `json:"instance"`
	RegionalPublicNKey        string `json:"regionalPublicNkey"`
	GlobalPublicNKey          string `json:"globalPublicNkey"`
	MembershipPublicKey       string `json:"membershipPublicKey"`
}
type Config struct {
	SourceQuiescence   *QuiescenceConfig          `json:"sourceQuiescence,omitempty"`
	StorageTransition  controltransition.Delivery `json:"storageTransition,omitzero"`
	PreliminaryCapture *PreliminaryCaptureConfig  `json:"preliminaryCapture,omitempty"`
	AuthorityReader    nodeauthority.ReaderConfig `json:"authorityReader"`
	Version            int                        `json:"version"`
	Mode               string                     `json:"mode"`
	Role               string                     `json:"role"`
	NodeID             string                     `json:"nodeId"`
	Cell               string                     `json:"cell"`
	Instance           string                     `json:"instance"`
	SeedInstance       string                     `json:"seedInstance"`
	Peers              []Peer                     `json:"peers"`
	Broker             Broker                     `json:"broker"`
	Regional           Store                      `json:"regional"`
	Global             *Store                     `json:"global"`
	Membership         Membership                 `json:"membership"`
	ProfileSHA256      string                     `json:"profileSha256"`
}

func ParseConfig(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 || len(raw) > MaximumConfigBytes {
		return c, errors.New("initialgrant: configuration exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(&struct{}{}) != io.EOF {
		return c, errors.New("initialgrant: malformed configuration")
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(raw, canonical) {
		return c, errors.New("initialgrant: configuration must be canonical with exact fields")
	}
	return c, c.Validate()
}
func cleanPath(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func token(s string) bool {
	_, err := hostmanifest.RequireToken(s, "identity", "initialgrant: invalid identity")
	return err == nil
}
func validMembershipPublic(s string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(raw)
	p, ok := key.(*ecdsa.PublicKey)
	return err == nil && ok && p.Curve == elliptic.P256()
}
func (t TLSFiles) valid() bool {
	return cleanPath(t.CAFile) && cleanPath(t.CertificateFile) && cleanPath(t.KeyFile) && hostmanifest.ValidDigest(t.CASHA256) && hostmanifest.ValidDigest(t.CertificateSHA256) && t.KeyFile != t.CertificateFile && t.KeyFile != t.CAFile
}
func (c Connection) valid() bool {
	return cleanPath(c.NKeySeedFile) && nkeys.IsValidPublicUserKey(c.PublicNKey) && c.TLS.valid() && c.NKeySeedFile != c.TLS.KeyFile
}
func (c Config) Validate() error {
	if err := c.validateQuiescence(); err != nil {
		return err
	}
	paths := []string{c.Broker.StoreDir}
	if c.PreliminaryCapture != nil {
		paths = append(paths, c.PreliminaryCapture.RequestFile, c.PreliminaryCapture.OutputDir)
		if c.PreliminaryCapture.Publication != nil {
			paths = append(paths, c.PreliminaryCapture.Publication.RequestFile, c.PreliminaryCapture.Publication.StateDir)
		}
	}
	if err := c.StorageTransition.Validate(paths...); err != nil {
		return err
	}
	if c.StorageTransition != (controltransition.Delivery{}) && c.Role != "seed" {
		return errors.New("initialgrant: only the seed can accept storage transition delivery")
	}
	bad := func() error {
		return errors.New("initialgrant: invalid initial GRU role, identity or finite configuration")
	}
	if err := c.AuthorityReader.Validate(); err != nil {
		return err
	}
	if c.AuthorityReader.Endpoint != c.Broker.Endpoint || c.AuthorityReader.ServerName != c.Broker.ServerName || c.AuthorityReader.Account != c.Regional.Account {
		return bad()
	}
	if c.Version != 1 || c.Mode != Mode || (c.Role != "seed" && c.Role != "participant") || c.Cell != "gru" || !token(c.NodeID) || !strings.HasPrefix(c.NodeID, "gru-") || !token(c.Instance) || !token(c.SeedInstance) || !hostmanifest.ValidDigest(c.ProfileSHA256) || !token(c.Broker.ServerName) || !cleanPath(c.Broker.StoreDir) || c.Broker.StorageBudgetBytes <= 0 {
		return bad()
	}
	u, err := url.Parse(c.Broker.Endpoint)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return bad()
	}
	if c.Regional.Account == "" || len(c.Regional.Account) > 63 || !c.Regional.Runtime.valid() || !cleanPath(c.Membership.SigningKeyFile) || !cleanPath(c.Membership.PinsFile) || !hostmanifest.ValidDigest(c.Membership.PinsSHA256) || !validMembershipPublic(c.Membership.PublicKey) {
		return bad()
	}
	if c.Role == "seed" {
		if c.Instance != c.SeedInstance || c.Global == nil || c.Regional.Provisioner == nil || c.Global.Provisioner == nil || !c.Regional.Provisioner.valid() || !c.Global.Provisioner.valid() || !c.Global.Runtime.valid() || c.Global.Account == "" || c.Global.Account == c.Regional.Account || !c.Broker.TLS.valid() || !json.Valid([]byte(c.Broker.Configuration)) || len(c.Broker.Configuration) > 32<<10 {
			return bad()
		}
		if capture := c.PreliminaryCapture; capture != nil {
			if !cleanPath(capture.RequestFile) || !cleanPath(capture.OutputDir) || capture.OutputDir == "/" || capture.MaxSnapshotBytes < 1024 || capture.MaxSnapshotBytes > 1<<30 || capture.MaxTotalBytes < capture.MaxSnapshotBytes || capture.MaxTotalBytes > 256<<30 || !capture.Regional.valid() || !capture.Global.valid() {
				return bad()
			}
			for _, path := range []string{c.Broker.StoreDir, capture.RequestFile} {
				if nestedPath(path, capture.OutputDir) || nestedPath(capture.OutputDir, path) {
					return bad()
				}
			}
			if publication := capture.Publication; publication != nil {
				if !cleanPath(publication.RequestFile) || !cleanPath(publication.StateDir) || publication.StateDir == "/" || !publication.Journal.valid() || ociinstance.ValidateConfig(publication.Identity) != nil {
					return bad()
				}
				for _, path := range []string{c.Broker.StoreDir, capture.OutputDir, capture.RequestFile, publication.RequestFile} {
					if nestedPath(path, publication.StateDir) || nestedPath(publication.StateDir, path) {
						return bad()
					}
				}
				if publication.RequestFile == capture.RequestFile {
					return bad()
				}
			}
		}
	} else if c.Instance == c.SeedInstance || c.Global != nil || c.Regional.Provisioner != nil || c.Broker.Configuration != "" || c.Broker.TLS != (TLSFiles{}) {
		return bad()
	}
	if c.Role != "seed" && c.PreliminaryCapture != nil {
		return bad()
	}
	if len(c.Peers) < 1 || len(c.Peers) > 3 {
		return bad()
	}
	seen := map[string]bool{}
	keys := map[string]bool{}
	membershipKeys := map[string]bool{}
	self, seed := false, false
	for index, p := range c.Peers {
		if !token(p.Instance) || seen[p.Instance] || index > 0 && c.Peers[index-1].Instance >= p.Instance || !nkeys.IsValidPublicUserKey(p.RegionalPublicNKey) || keys[p.RegionalPublicNKey] || !validMembershipPublic(p.MembershipPublicKey) || membershipKeys[p.MembershipPublicKey] {
			return bad()
		}
		if !nkeys.IsValidPublicUserKey(p.AuthorityReaderPublicNKey) || keys[p.AuthorityReaderPublicNKey] || p.AuthorityReaderPublicNKey == p.RegionalPublicNKey {
			return bad()
		}
		keys[p.AuthorityReaderPublicNKey] = true
		seen[p.Instance] = true
		membershipKeys[p.MembershipPublicKey] = true
		keys[p.RegionalPublicNKey] = true
		if p.Instance == c.SeedInstance {
			if !nkeys.IsValidPublicUserKey(p.GlobalPublicNKey) || keys[p.GlobalPublicNKey] {
				return bad()
			}
			keys[p.GlobalPublicNKey] = true
			seed = true
		} else if p.GlobalPublicNKey != "" {
			return bad()
		}
		if p.Instance == c.Instance {
			self = p.AuthorityReaderPublicNKey == c.AuthorityReader.PublicNKey && p.RegionalPublicNKey == c.Regional.Runtime.PublicNKey && p.MembershipPublicKey == c.Membership.PublicKey
			if c.Role == "seed" && p.GlobalPublicNKey != c.Global.Runtime.PublicNKey {
				return bad()
			}
		}
	}
	if !self || !seed {
		return bad()
	}
	if c.Role == "seed" {
		connections := []*Connection{c.Regional.Provisioner, c.Global.Provisioner}
		if c.SourceQuiescence != nil {
			connections = append(connections, &c.SourceQuiescence.Regional, &c.SourceQuiescence.Global)
		}
		if c.PreliminaryCapture != nil {
			connections = append(connections, &c.PreliminaryCapture.Regional, &c.PreliminaryCapture.Global)
			if c.PreliminaryCapture.Publication != nil {
				connections = append(connections, &c.PreliminaryCapture.Publication.Journal)
			}
		}
		for _, conn := range connections {
			if keys[conn.PublicNKey] {
				return bad()
			}
			keys[conn.PublicNKey] = true
		}
	}
	return nil
}

func nestedPath(path, parent string) bool {
	return path == parent || strings.HasPrefix(path, strings.TrimSuffix(parent, "/")+"/")
}

// ComponentConfig recognizes only the exact initial launch vocabulary. A
// malformed attempted initial mode is an error, never an ordinary component.
func ComponentConfig(spec hostmanifest.ComponentSpec) (Config, bool, error) {
	if spec.Name != "orchestrator" {
		return Config{}, false, nil
	}
	fields := strings.Fields(spec.Arguments)
	if len(fields) == 0 || fields[0] != Mode {
		return Config{}, false, nil
	}
	if spec.Arguments != Arguments {
		return Config{}, true, errors.New("initialgrant: initial launch arguments differ")
	}
	c, err := ParseConfig([]byte(spec.Configuration))
	if err == nil {
		err = c.StorageTransition.Validate(spec.DataVolume)
	}
	return c, true, err
}
