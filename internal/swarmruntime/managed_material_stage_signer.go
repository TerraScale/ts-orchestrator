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

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/moby/swarmkit/v2/api"
)

// SignManagedMaterialStage is an isolated source candidate: production wiring
// requires independently established accepted key-creation custody. Present
// filesystem safety cannot prove that an existing native key was never copied.
// Domain admission and durable first-append custody remain separate requirements.
func (n *Node) SignManagedMaterialStage(ctx context.Context, call rootoci.Call, ownhost *ControllerHostBinding,
	session *host.ManagerRuntimeSession, stage managedmaterial.MaterialStage, beforeSign func(context.Context) error,
) (managedmaterial.SignedMaterialStage, error) {
	var empty managedmaterial.SignedMaterialStage
	if os.Geteuid() != 0 || n == nil || n.upstream == nil || n.role != "manager" || ctx == nil ||
		ownhost == nil || session == nil || beforeSign == nil || stage.Native.NodeID != n.ID() ||
		stage.Native.InstanceID != n.admission.InstanceID || stage.Native.OCIRegion != n.admission.Region {
		return empty, errors.New("managed material stage requires the actual root-owned manager and ownhost")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !deadline.Equal(stage.OriginalContextExpiresAt) || ctx.Err() != nil {
		return empty, errors.New("managed material stage requires its original bounded context")
	}
	wire, err := managedmaterial.MaterialStageSigningBytes(stage)
	if err != nil {
		return empty, err
	}
	// Retain canonical owned bytes so callbacks cannot change a slice or candidate
	// between admission, key use and delivery.
	var retained managedmaterial.MaterialStage
	if err := protocol.DecodeStrict(wire[len("TS-MANAGED-MATERIAL-STAGE-V1\x00"):], &retained, 384<<10); err != nil {
		return empty, err
	}
	stage = retained
	identity := ownhost.Identity()
	if identity.Cell != stage.Cell || identity.InstanceID != stage.Native.InstanceID || identity.OCIRegion != stage.Native.OCIRegion {
		return empty, errors.New("managed material stage differs from the accepted ownhost identity")
	}
	callerGuard := func() error {
		if ctx.Err() != nil || !time.Now().Before(deadline) || stage.AdmittedAt.After(time.Now()) ||
			!time.Now().Before(stage.ExpiresAt) || !time.Now().Before(stage.CredentialExpiresAt) ||
			!time.Now().Before(stage.LeaseExpiresAt) || call.RuntimeID() != stage.RuntimeID {
			return errors.New("managed material stage original operation is no longer current")
		}
		if err := call.Guard(ctx); err != nil {
			return err
		}
		digest, expires, err := call.AuthorityBindingSHA256(ctx)
		if err != nil || digest != stage.CallerAuthoritySHA256 || !expires.Equal(stage.OriginalCallerExpiresAt) {
			return errors.New("managed material stage differs from its actual admitted caller")
		}
		return ctx.Err()
	}
	if err := callerGuard(); err != nil {
		return empty, err
	}
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	control, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return empty, err
	}
	key, chain, err := n.nodeSigningKey()
	if err != nil {
		return empty, err
	}
	defer key.Close()
	if len(chain) == 0 || len(chain) > 8 {
		return empty, errors.New("managed material stage native certificate is unavailable")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return empty, err
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !leaf.NotAfter.Equal(stage.NativeCertificateExpiresAt) {
		return empty, errors.New("managed material stage requires its exact native ECDSA certificate")
	}
	certificateDigest := sha256.Sum256(chain[0])
	if stage.Native.CertificateSHA256 != hex.EncodeToString(certificateDigest[:]) {
		return empty, errors.New("managed material stage native certificate changed")
	}
	matchSource := func(name managedmaterial.MaterialStageSourceName, revision uint64, payload []byte) error {
		for _, source := range stage.Sources {
			if source.Name == name {
				if source.Revision != revision || !bytes.Equal(source.Payload, payload) {
					return errors.New("managed material stage actual source changed: " + string(name))
				}
				return nil
			}
		}
		return errors.New("managed material stage actual source is missing: " + string(name))
	}
	var managerCertificate, clusterCA []byte
	nativeGuard := func() error {
		if err := session.Revalidate(ctx); err != nil {
			return err
		}
		registration, err := ownhost.currentRegistration(ctx)
		if err != nil || ownhost.Identity() != identity || registration.ID != ownhost.HostID() {
			return errors.New("managed material stage ownhost admission changed")
		}
		accepted, err := bootstrapstart.EncodeAcceptedIdentity(ownhost.accepted)
		if err != nil {
			return err
		}
		if err := matchSource(managedmaterial.MaterialStageAcceptedIdentity, 0, accepted); err != nil {
			return err
		}
		registrationWire, err := protocol.EncodeJSON(registration)
		if err != nil {
			return err
		}
		sessionRegistration, err := protocol.EncodeJSON(session.Registration())
		if err != nil || !bytes.Equal(sessionRegistration, registrationWire) {
			return errors.New("managed material stage session differs from actual ownhost registration")
		}
		ownhostWire, err := protocol.EncodeJSON(managedmaterial.MaterialStageOwnhostSource{
			Registration: registration, RegistrationRevision: session.RegistrationRevision(), SourceRevision: session.SourceRevision(),
			SessionID: session.SessionID(), SessionEpoch: session.SessionEpoch(), SessionSourceExpiresAt: session.SessionSourceExpiresAt(),
		})
		if err != nil {
			return err
		}
		if err := matchSource(managedmaterial.MaterialStageOwnhost, session.SourceRevision(), ownhostWire); err != nil {
			return err
		}
		got, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: n.ID()})
		if err != nil || got == nil || got.Node == nil {
			return errors.New("managed material stage native manager is unavailable")
		}
		manager := got.Node
		if manager.ID != n.ID() || manager.Role != api.NodeRoleManager || manager.Spec.DesiredRole != api.NodeRoleManager ||
			manager.Spec.Membership != api.NodeMembershipAccepted || manager.Spec.Annotations.Name != n.admission.HostID ||
			manager.Spec.Annotations.Labels[LabelInstanceID] != stage.Native.InstanceID || manager.Spec.Annotations.Labels[LabelRegion] != stage.Native.OCIRegion ||
			manager.Spec.Annotations.Labels[LabelHostRole] != "manager" || manager.Certificate.CN != n.ID() || manager.Certificate.Role != api.NodeRoleManager {
			return errors.New("managed material stage requires the exact accepted native manager")
		}
		block, rest := pem.Decode(manager.Certificate.Certificate)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, chain[0]) {
			return errors.New("managed material stage actual native certificate changed")
		}
		managerWire, err := protocol.EncodeJSON(manager)
		if err != nil {
			return err
		}
		if err := matchSource(managedmaterial.MaterialStageNativeManager, manager.Meta.Version.Index, managerWire); err != nil {
			return err
		}
		cluster, err := control.ClusterIdentity(ctx)
		if err != nil || cluster == nil || cluster.ID != stage.Native.SwarmClusterID || len(cluster.RootCACert) == 0 {
			return errors.New("managed material stage actual native cluster changed")
		}
		clusterDigest := sha256.Sum256(cluster.RootCACert)
		if stage.Native.ClusterCASHA256 != hex.EncodeToString(clusterDigest[:]) {
			return errors.New("managed material stage actual native cluster authority changed")
		}
		clusterWire, err := protocol.EncodeJSON(cluster)
		if err != nil {
			return err
		}
		if err := matchSource(managedmaterial.MaterialStageNativeCluster, 0, clusterWire); err != nil {
			return err
		}
		managerCertificate, clusterCA = bytes.Clone(manager.Certificate.Certificate), bytes.Clone(cluster.RootCACert)
		if err := session.Revalidate(ctx); err != nil {
			return err
		}
		return callerGuard()
	}
	if err := nativeGuard(); err != nil {
		return empty, err
	}
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	if err := nativeGuard(); err != nil {
		return empty, err
	}
	digest := sha256.Sum256(wire)
	if err := callerGuard(); err != nil {
		return empty, err
	}
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return empty, err
	}
	signed := managedmaterial.SignedMaterialStage{Stage: stage, CertificateChain: chain, Signature: signature}
	if err := beforeSign(ctx); err != nil {
		return empty, err
	}
	if err := nativeGuard(); err != nil {
		return empty, err
	}
	if err := managedmaterial.VerifySignedMaterialStage(signed, managerCertificate, clusterCA, stage.Native.SwarmClusterID, time.Now()); err != nil {
		return empty, err
	}
	if err := callerGuard(); err != nil {
		return empty, err
	}
	return signed, nil
}
