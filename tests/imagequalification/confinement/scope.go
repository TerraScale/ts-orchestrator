// Package confinement observes disposable OCI authority through real SDK APIs.
// It has no IAM writes and belongs only to the image qualification harness.
package confinement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Scope is copied from the independently signed finite qualification approval.
// ApprovalSHA256 binds its complete host, byte and spending limits as well.
type Scope struct {
	ApprovalSHA256, RunID, Tenancy, Principal, Group, PolicyID string
	Compartment, Subnet, Namespace, Bucket, Object             string
	RunnerCIDR, PeerCIDR, VCNCIDR                              string
	HostNames                                                  []string
	ExistingHosts                                              map[string]string
	PolicyStatements                                           []string
	ExpiresAt, CleanupUntil                                    time.Time
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9._:/-]+$`)

func (s Scope) validate(now time.Time) error {
	digest, err := hex.DecodeString(s.ApprovalSHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("confinement requires exact signed approval digest")
	}
	for _, value := range []string{s.RunID, s.Tenancy, s.Principal, s.Group, s.PolicyID, s.Compartment, s.Subnet, s.Namespace, s.Bucket, s.Object} {
		if !identifier.MatchString(value) {
			return errors.New("invalid confinement scope identifier")
		}
	}
	if s.Tenancy == s.Compartment || !now.Before(s.CleanupUntil) || s.ExpiresAt.After(s.CleanupUntil) || s.CleanupUntil.Sub(s.ExpiresAt) > 24*time.Hour {
		return errors.New("confinement requires dedicated compartment and finite cleanup authority")
	}
	for _, value := range []string{s.RunnerCIDR, s.PeerCIDR, s.VCNCIDR} {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() || (value != s.VCNCIDR && prefix.Bits() < 24) {
			return errors.New("confinement requires exact private IPv4 networks and narrow runner/peer prefixes")
		}
	}
	vcn, _ := netip.ParsePrefix(s.VCNCIDR)
	peer, _ := netip.ParsePrefix(s.PeerCIDR)
	runner, _ := netip.ParsePrefix(s.RunnerCIDR)
	if !vcn.Contains(peer.Addr()) || !vcn.Contains(runner.Addr()) || vcn.Bits() > min(peer.Bits(), runner.Bits()) || peer.Overlaps(runner) {
		return errors.New("runner and peers require disjoint subnets within approved VCN")
	}
	if len(s.HostNames) == 0 || len(s.HostNames) > 4 || len(s.ExistingHosts) > len(s.HostNames) {
		return errors.New("confinement requires finite approved hosts")
	}
	seen := map[string]bool{}
	for _, name := range s.HostNames {
		if !identifier.MatchString(name) || seen[name] {
			return errors.New("invalid or duplicate approved host name")
		}
		seen[name] = true
	}
	seen = map[string]bool{}
	for id, name := range s.ExistingHosts {
		if !strings.HasPrefix(id, "ocid1.instance.") || !slices.Contains(s.HostNames, name) || seen[name] {
			return errors.New("unexpected existing host journal identity")
		}
		seen[name] = true
	}
	if !slices.Equal(s.PolicyStatements, RequiredStatements(s)) {
		return errors.New("approved policy differs from canonical disposable operations")
	}
	return nil
}

// RequiredStatements excludes IAM, Vault, tagging and instance metadata updates.
// Creation expires first; only observation and destructive cleanup remain later.
func RequiredStatements(s Scope) []string {
	statement := func(resource, conditions string, deadline time.Time, operations ...string) string {
		parts := make([]string, len(operations))
		for i, operation := range operations {
			parts[i] = "request.operation='" + operation + "'"
		}
		return fmt.Sprintf("Allow group id %s to %s in compartment id %s where all {request.utc-timestamp < '%s', %sany {%s}}", s.Group, resource, s.Compartment, deadline.UTC().Format(time.RFC3339), conditions, strings.Join(parts, ", "))
	}
	object := fmt.Sprintf("target.bucket.name='%s', target.object.name='%s', ", s.Bucket, s.Object)
	return []string{
		statement("manage instance-family", "", s.ExpiresAt, "CreateImage", "LaunchInstance"),
		statement("manage instance-family", "", s.CleanupUntil, "GetImage", "GetInstance", "ListVnicAttachments", "TerminateInstance", "DeleteImage"),
		statement("use virtual-network-family", fmt.Sprintf("target.subnet.id='%s', ", s.Subnet), s.ExpiresAt, "LaunchInstance"),
		statement("read virtual-network-family", "", s.CleanupUntil, "GetVnic", "GetSubnet"),
		statement("manage objects", object, s.ExpiresAt, "PutObject", "CreateMultipartUpload", "UploadPart", "CommitMultipartUpload"),
		statement("manage objects", object, s.CleanupUntil, "HeadObject", "DeleteObject", "AbortMultipartUpload"),
	}
}

func clone(s Scope) Scope {
	s.PolicyStatements = slices.Clone(s.PolicyStatements)
	s.HostNames = slices.Clone(s.HostNames)
	s.ExistingHosts = maps.Clone(s.ExistingHosts)
	return s
}

func immutableScope(s Scope) Scope { s.ExistingHosts = nil; return s }

func hash(value any) string {
	wire, _ := json.Marshal(value)
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
