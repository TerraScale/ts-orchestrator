// Package controltransition defines the finite owner's storage-transition plan.
// Verification is an admission input, never evidence of completed storage
// effects or permission to run ordinary authority workers.
package controltransition

import (
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

const MaximumBytes = 1 << 20
const Mode = "transition-control-r1-to-r3"

// Plan binds identities and intended effects before the source stops. Receipt
// object keys are derived beneath each Prefix using the signed plan digest;
// final archive digests are supplied by chained capture receipts, not guessed
// before the final cut. All SHA256 fields use bare lower-case hexadecimal.
type Plan struct {
	Version               int           `json:"version"`
	Mode                  string        `json:"mode"`
	EstateID              string        `json:"estateId"`
	TransitionID          string        `json:"transitionId"`
	IssuedAt              time.Time     `json:"issuedAt"`
	ExpiresAt             time.Time     `json:"expiresAt"`
	Source                Source        `json:"source"`
	ClusterName           string        `json:"clusterName"`
	TrustBundleSHA256     string        `json:"trustBundleSha256"`
	SourceTopologyEpoch   uint64        `json:"sourceTopologyEpoch"`
	TargetTopologyEpoch   uint64        `json:"targetTopologyEpoch"`
	GlobalElectionFloor   int64         `json:"globalElectionFloor"`
	RegionalElectionFloor int64         `json:"regionalElectionFloor"`
	Destinations          []Destination `json:"destinations"`
	Accounts              []Account     `json:"accounts"`
	Limits                Limits        `json:"limits"`
}

type Source struct {
	NodeID                string `json:"nodeId"`
	ServerName            string `json:"serverName"`
	BootstrapGrantSHA256  string `json:"bootstrapGrantSha256"`
	InitialManifestSHA256 string `json:"initialManifestSha256"`
	CaptureManifestSHA256 string `json:"captureManifestSha256"`
	LaunchSHA256          string `json:"launchSha256"`
	StoreScopeSHA256      string `json:"storeScopeSha256"`
	ProfileSHA256         string `json:"profileSha256"`
	StoreDir              string `json:"storeDir"`
	CaptureDir            string `json:"captureDir"`
	ArchiveDir            string `json:"archiveDir"`
	ReceiptPublicKeyPEM   string `json:"receiptPublicKeyPem"`
}

type Destination struct {
	Region                   string         `json:"region"`
	NodeID                   string         `json:"nodeId"`
	ServerName               string         `json:"serverName"`
	BootstrapGrantSHA256     string         `json:"bootstrapGrantSha256"`
	PreparedManifestSHA256   string         `json:"preparedManifestSha256"`
	ActivationManifestSHA256 string         `json:"activationManifestSha256"`
	RouteURL                 string         `json:"routeUrl"`
	CertificateSHA256        string         `json:"certificateSha256"`
	ReceiptPublicKeyPEM      string         `json:"receiptPublicKeyPem"`
	PreliminaryStoreDir      string         `json:"preliminaryStoreDir"`
	StoreDir                 string         `json:"storeDir"`
	StagingDir               string         `json:"stagingDir"`
	Objects                  ObjectLocation `json:"objects"`
}

// ObjectLocation identifies one already observed OCI bucket. The observation
// digest binds the ownership evidence to be checked at admission and use.
type ObjectLocation struct {
	OCIRegion                  string `json:"ociRegion"`
	Namespace                  string `json:"namespace"`
	Bucket                     string `json:"bucket"`
	BucketResourceID           string `json:"bucketResourceId"`
	CompartmentID              string `json:"compartmentId"`
	OwnershipObservationSHA256 string `json:"ownershipObservationSha256"`
	Prefix                     string `json:"prefix"`
}

type Account struct {
	Role            string   `json:"role"`
	SourceName      string   `json:"sourceName"`
	DestinationName string   `json:"destinationName"`
	Streams         []Stream `json:"streams"`
}

// Configuration digests bind the source configuration and the intended final
// R3 configuration. Temporary R1 restore placement is a separate phase, not
// authorization for ordinary R1 election or application writes.
type Stream struct {
	Name               string     `json:"name"`
	SourceConfigSHA256 string     `json:"sourceConfigSha256"`
	FinalConfigSHA256  string     `json:"finalConfigSha256"`
	Consumers          []Consumer `json:"consumers"`
}

type Consumer struct {
	Name               string `json:"name"`
	Durable            bool   `json:"durable"`
	SourceConfigSHA256 string `json:"sourceConfigSha256"`
	FinalConfigSHA256  string `json:"finalConfigSha256"`
}

type Limits struct {
	MaxStoreBytes    int64 `json:"maxStoreBytes"`
	MaxStoreFiles    int64 `json:"maxStoreFiles"`
	MaxSnapshotBytes int64 `json:"maxSnapshotBytes"`
	MaxTransferBytes int64 `json:"maxTransferBytes"`
	MaxRestoreBytes  int64 `json:"maxRestoreBytes"`
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func token(s string) bool {
	_, err := hostmanifest.RequireToken(s, "identity", "controltransition: invalid identity")
	return err == nil
}

func name(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func separatePaths(paths ...string) bool {
	for i, path := range paths {
		if !hostmanifest.SafeAbsolutePath(path) {
			return false
		}
		for _, prior := range paths[:i] {
			if hostmanifest.PathsOverlap(path, prior) {
				return false
			}
		}
	}
	return true
}

func (p Plan) Validate() error {
	bad := errors.New("controltransition: invalid finite transition plan")
	if p.Version != 1 || p.Mode != Mode || !token(p.EstateID) || !token(p.TransitionID) || p.IssuedAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 24*time.Hour || !token(p.ClusterName) || !validDigest(p.TrustBundleSHA256) || p.SourceTopologyEpoch == 0 || p.TargetTopologyEpoch <= p.SourceTopologyEpoch || p.GlobalElectionFloor <= 0 || p.GlobalElectionFloor == math.MaxInt64 || p.RegionalElectionFloor <= 0 || p.RegionalElectionFloor == math.MaxInt64 || len(p.Destinations) != 3 || len(p.Accounts) != 2 {
		return bad
	}
	s := p.Source
	if !token(s.NodeID) || !strings.HasPrefix(s.NodeID, "gru-") || !token(s.ServerName) || !separatePaths(s.StoreDir, s.CaptureDir, s.ArchiveDir) || s.InitialManifestSHA256 == s.CaptureManifestSHA256 {
		return bad
	}
	for _, hash := range []string{s.BootstrapGrantSHA256, s.InitialManifestSHA256, s.CaptureManifestSHA256, s.LaunchSHA256, s.StoreScopeSHA256, s.ProfileSHA256} {
		if !validDigest(hash) {
			return bad
		}
	}
	sourceKey, err := publicKeyID([]byte(s.ReceiptPublicKeyPEM))
	if err != nil {
		return bad
	}
	nodes, servers, routes, certificates, keys, buckets := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, region := range []string{"gru", "sfo", "fra"} {
		d := p.Destinations[i]
		key, err := publicKeyID([]byte(d.ReceiptPublicKeyPEM))
		if err != nil || d.Region != region || !token(d.NodeID) || !strings.HasPrefix(d.NodeID, region+"-") || !token(d.ServerName) || d.ServerName == s.ServerName || nodes[d.NodeID] || servers[d.ServerName] || routes[d.RouteURL] || certificates[d.CertificateSHA256] || keys[key] || !validRoute(d.RouteURL) || !validDigest(d.CertificateSHA256) || !validDigest(d.BootstrapGrantSHA256) || !validDigest(d.PreparedManifestSHA256) || !validDigest(d.ActivationManifestSHA256) || d.PreparedManifestSHA256 == d.ActivationManifestSHA256 || !separatePaths(d.PreliminaryStoreDir, d.StoreDir, d.StagingDir) {
			return bad
		}
		if d.NodeID == s.NodeID {
			if d.BootstrapGrantSHA256 != s.BootstrapGrantSHA256 || !separatePaths(s.StoreDir, s.CaptureDir, s.ArchiveDir, d.PreliminaryStoreDir, d.StoreDir, d.StagingDir) {
				return bad
			}
		} else if key == sourceKey {
			return bad
		}
		nodes[d.NodeID], servers[d.ServerName], routes[d.RouteURL], certificates[d.CertificateSHA256], keys[key] = true, true, true, true, true
		if !d.Objects.valid(region) || buckets[d.Objects.BucketResourceID] {
			return bad
		}
		buckets[d.Objects.BucketResourceID] = true
	}
	sources, targets := map[string]bool{}, map[string]bool{}
	for i, role := range []string{"global", "gru-regional"} {
		a := p.Accounts[i]
		if a.Role != role || !name(a.SourceName) || !name(a.DestinationName) || sources[a.SourceName] || targets[a.DestinationName] || len(a.Streams) == 0 || len(a.Streams) > 128 {
			return bad
		}
		sources[a.SourceName], targets[a.DestinationName] = true, true
		for j, stream := range a.Streams {
			if !name(stream.Name) || j > 0 && stream.Name <= a.Streams[j-1].Name || !validDigest(stream.SourceConfigSHA256) || !validDigest(stream.FinalConfigSHA256) || len(stream.Consumers) > 1024 {
				return bad
			}
			for k, consumer := range stream.Consumers {
				if !name(consumer.Name) || k > 0 && consumer.Name <= stream.Consumers[k-1].Name || !validDigest(consumer.SourceConfigSHA256) || !validDigest(consumer.FinalConfigSHA256) {
					return bad
				}
			}
		}
	}
	l := p.Limits
	if l.MaxStoreBytes < 1024 || l.MaxStoreBytes > 256<<30 || l.MaxStoreFiles < 1 || l.MaxStoreFiles > 1<<20 || l.MaxSnapshotBytes < 1024 || l.MaxSnapshotBytes > 1<<30 || l.MaxTransferBytes < l.MaxSnapshotBytes || l.MaxTransferBytes > 256<<30 || l.MaxRestoreBytes < l.MaxSnapshotBytes || l.MaxRestoreBytes > 256<<30 {
		return bad
	}
	return nil
}

func validRoute(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "nats-route" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != value {
		return false
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, portErr := strconv.Atoi(port)
	if err != nil || host == "" || len(host) > 253 || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && !address.IsUnspecified() && !address.IsMulticast()
	}
	for label := range strings.SplitSeq(host, ".") {
		if !token(label) {
			return false
		}
	}
	return true
}

func (o ObjectLocation) valid(region string) bool {
	want := map[string]string{"gru": "sa-saopaulo-1", "sfo": "us-sanjose-1", "fra": "eu-frankfurt-1"}[region]
	if o.OCIRegion != want || !token(o.Namespace) || !token(o.Bucket) || !strings.HasPrefix(o.BucketResourceID, "ocid1.bucket.") || !strings.HasPrefix(o.CompartmentID, "ocid1.compartment.") || len(o.BucketResourceID) > 512 || len(o.CompartmentID) > 512 || !validDigest(o.OwnershipObservationSHA256) || len(o.Prefix) == 0 || len(o.Prefix) > 512 {
		return false
	}
	for _, id := range []string{o.BucketResourceID, o.CompartmentID} {
		for _, r := range id {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.') {
				return false
			}
		}
	}
	for part := range strings.SplitSeq(o.Prefix, "/") {
		if !token(part) {
			return false
		}
	}
	return true
}

func CanonicalPlan(p Plan) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaximumBytes {
		return nil, errors.New("controltransition: plan exceeds document bound")
	}
	return raw, nil
}
