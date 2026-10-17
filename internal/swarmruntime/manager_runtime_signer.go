package swarmruntime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/moby/swarmkit/v2/api"
)

// SignManagerRuntimeBinding signs only the finite manager-session identity.
// Root's retained admission must recheck its actual process, host and signed
// sources at key use and delivery; no private key or arbitrary signer escapes.
func (n *Node) SignManagerRuntimeBinding(ctx context.Context, binding host.ManagerRuntimeBinding, beforeSign func(context.Context) error) (host.SignedManagerRuntimeBinding, error) {
	var empty host.SignedManagerRuntimeBinding
	if os.Geteuid() != 0 || n == nil || n.upstream == nil || n.role != "manager" || ctx == nil || beforeSign == nil ||
		binding.NodeID != n.ID() || binding.InstanceID != n.admission.InstanceID || binding.OCIRegion != n.admission.Region ||
		binding.IssuedAt.After(time.Now()) || !time.Now().Before(binding.ExpiresAt) {
		return empty, errors.New("manager runtime signing requires the actual root-owned manager")
	}
	originalDeadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || !time.Now().Before(originalDeadline) || binding.ExpiresAt.After(originalDeadline) {
		return empty, errors.New("manager runtime signing requires the original bounded operation")
	}
	ctx, cancel := context.WithDeadline(ctx, binding.ExpiresAt)
	defer cancel()
	wire, err := host.ManagerRuntimeSigningBytes(binding)
	if err != nil {
		return empty, err
	}
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	control, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return empty, err
	}
	cluster, err := control.ClusterIdentity(ctx)
	if err != nil || cluster == nil || cluster.ID != binding.SwarmClusterID || len(cluster.RootCACert) == 0 {
		return empty, errors.New("manager runtime binding differs from the actual native cluster")
	}
	clusterDigest := sha256.Sum256(cluster.RootCACert)
	if binding.ClusterCASHA256 != hex.EncodeToString(clusterDigest[:]) {
		return empty, errors.New("manager runtime binding differs from the actual native cluster authority")
	}
	key, chain, err := n.nodeSigningKey()
	if err != nil {
		return empty, err
	}
	if len(chain) == 0 || len(chain) > 8 {
		return empty, errors.New("manager runtime signing identity is unavailable")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return empty, err
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		return empty, errors.New("manager runtime signing requires the native ECDSA certificate")
	}
	certificateDigest := sha256.Sum256(chain[0])
	if binding.CertificateSHA256 != hex.EncodeToString(certificateDigest[:]) || binding.ExpiresAt.After(leaf.NotAfter) ||
		leaf.Subject.CommonName != n.ID() || len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != "swarm-manager" ||
		len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != cluster.ID {
		return empty, errors.New("manager runtime binding differs from the original native signing certificate")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cluster.RootCACert) {
		return empty, errors.New("manager runtime native certificate authority is unavailable")
	}
	total := 0
	for i, raw := range chain {
		total += len(raw)
		if total > 64<<10 {
			return empty, errors.New("manager runtime native certificate chain exceeds its bound")
		}
		if i > 0 {
			certificate, err := x509.ParseCertificate(raw)
			if err != nil {
				return empty, err
			}
			intermediates.AddCert(certificate)
		}
	}
	for _, at := range []time.Time{time.Now(), binding.ExpiresAt} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return empty, err
		}
	}
	var managerCertificate []byte
	currentManager := func(ctx context.Context) error {
		got, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
		if err != nil || got == nil || got.Node == nil {
			return errors.New("manager runtime native manager is unavailable")
		}
		manager := got.Node
		if manager.ID != binding.NodeID || manager.Role != api.NodeRoleManager || manager.Spec.DesiredRole != api.NodeRoleManager ||
			manager.Spec.Membership != api.NodeMembershipAccepted || manager.Spec.Annotations.Name != n.admission.HostID ||
			manager.Spec.Annotations.Labels[LabelInstanceID] != binding.InstanceID || manager.Spec.Annotations.Labels[LabelRegion] != binding.OCIRegion ||
			manager.Spec.Annotations.Labels[LabelHostRole] != "manager" || manager.Certificate.CN != binding.NodeID || manager.Certificate.Role != api.NodeRoleManager {
			return errors.New("manager runtime requires the exact accepted native manager")
		}
		block, _ := pem.Decode(manager.Certificate.Certificate)
		if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, chain[0]) ||
			managerCertificate != nil && !bytes.Equal(managerCertificate, manager.Certificate.Certificate) {
			return errors.New("manager runtime native certificate changed")
		}
		currentCluster, err := control.ClusterIdentity(ctx)
		if err != nil || currentCluster == nil || currentCluster.ID != cluster.ID || !bytes.Equal(currentCluster.RootCACert, cluster.RootCACert) {
			return errors.New("manager runtime native cluster identity changed")
		}
		managerCertificate = bytes.Clone(manager.Certificate.Certificate)
		return ctx.Err()
	}
	if err := currentManager(ctx); err != nil {
		return empty, err
	}
	digest := sha256.Sum256(wire)
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	if ctx.Err() != nil || !time.Now().Before(binding.ExpiresAt) || !time.Now().Before(originalDeadline) {
		return empty, context.DeadlineExceeded
	}
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return empty, err
	}
	signed := host.SignedManagerRuntimeBinding{Binding: binding, CertificateChain: chain, Signature: signature}
	if err := currentManager(ctx); err != nil {
		return empty, err
	}
	if err := host.VerifySignedManagerRuntimeBinding(signed, managerCertificate, cluster.RootCACert, cluster.ID, time.Now()); err != nil {
		return empty, err
	}
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	if ctx.Err() != nil || !time.Now().Before(binding.ExpiresAt) || !time.Now().Before(originalDeadline) {
		return empty, context.DeadlineExceeded
	}
	return signed, nil
}
