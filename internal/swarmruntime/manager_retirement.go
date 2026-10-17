//go:build linux

package swarmruntime

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

const managerRetirementLabel = "terrascale.manager-retirement"

// ManagerRetirementResult reports the native stage. DemotionVersion is the
// observed node version carrying the same immutable retirement operation.
type ManagerRetirementResult struct {
	Stage           string
	DemotionVersion uint64
}

type managerRetirementPin struct {
	NodeID, InstanceID, Slot, Region, RetirementSHA256, CertificateSHA256 string
	PreviousAttempt, OriginalVersion, LeaseEpoch, RaftTerm, RaftLeader    uint64
}

// RetireControllerManager uses only root-retired/current-terminated evidence
// and the actual applied node. It never looks up a replacement by slot name and
// never forces removal. An ambiguous result must retain this exact operation.
func (n *Node) RetireControllerManager(ctx context.Context, proof *bootstrapstart.ManagerRetirement, expectedNodeID string, expectedVersion, epoch uint64) (*ManagerRetirementResult, error) {
	if n == nil || ctx == nil || proof == nil || expectedNodeID == "" || expectedVersion == 0 || epoch == 0 ||
		n.upstream == nil || n.role != "manager" || expectedNodeID == n.ID() {
		return nil, errors.New("manager retirement requires exact admitted old node and original version")
	}
	bounded, cancel, err := proof.OperationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	ctx = bounded
	if err := proof.Verify(ctx); err != nil {
		return nil, err
	}
	reader, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return nil, err
	}
	// The privileged reader checks the original local admission independently.
	if _, err := reader.ClusterIdentity(ctx); err != nil {
		return nil, err
	}
	upstream, admitted, selfID := n.upstream, n.admission, n.ID()
	m := upstream.Manager()
	if m == nil || admitted.Region != proof.OCIRegion() {
		return nil, errors.New("retirement belongs to another admitted region")
	}
	var target *api.Node
	var cluster *api.Cluster
	var nodes []*api.Node
	observed, err := m.Observe(nil, func(tx store.ReadTx) error {
		target = store.GetNode(tx, expectedNodeID)
		var err error
		nodes, err = store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		clusters, err := store.FindClusters(tx, store.All)
		if err != nil || len(clusters) != 1 {
			return errors.New("retirement requires one current native cluster")
		}
		cluster = clusters[0]
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer observed.Cancel()
	if !managerRetirementNode(target, proof.Slot(), proof.PriorInstanceID(), proof.OCIRegion()) {
		return nil, errors.New("retirement old node mapping changed or is absent")
	}
	if err := managerRetirementCertificate(target, cluster); err != nil {
		return nil, err
	}
	pin := managerRetirementPin{NodeID: target.ID, InstanceID: proof.PriorInstanceID(), Slot: proof.Slot(), Region: proof.OCIRegion(),
		RetirementSHA256: proof.RetirementSHA256(), CertificateSHA256: managerRetirementDigest(target.Certificate.Certificate),
		PreviousAttempt: proof.PreviousAttempt(), OriginalVersion: expectedVersion, LeaseEpoch: epoch, RaftTerm: observed.Term, RaftLeader: observed.Leader}
	retained := target.Spec.Annotations.Labels[managerRetirementLabel]
	if retained != "" {
		var original managerRetirementPin
		if protocol.DecodeStrict([]byte(retained), &original, 8<<10) != nil || original.NodeID != pin.NodeID || original.InstanceID != pin.InstanceID ||
			original.Slot != pin.Slot || original.Region != pin.Region || original.RetirementSHA256 != pin.RetirementSHA256 ||
			original.CertificateSHA256 != pin.CertificateSHA256 || original.PreviousAttempt != pin.PreviousAttempt || original.OriginalVersion != expectedVersion ||
			original.LeaseEpoch == 0 || original.RaftTerm == 0 || original.RaftLeader == 0 || target.Spec.DesiredRole != api.NodeRoleWorker ||
			target.Spec.Availability != api.NodeAvailabilityPause {
			return nil, errors.New("partial manager demotion differs from its immutable original retirement")
		}
		pin = original
	} else if target.Meta.Version.Index != expectedVersion || target.Role != api.NodeRoleManager || target.Spec.DesiredRole != api.NodeRoleManager {
		return nil, errors.New("unstarted manager retirement requires the original manager version")
	}
	members, err := m.RaftMembersAtObservation(observed)
	if err != nil {
		return nil, err
	}
	if err := checkRetirementSurvivors(proof, target, nodes, members, cluster); err != nil {
		return nil, err
	}
	live := func(tx store.ReadTx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !proof.Valid(time.Now()) {
			return errors.New("original retirement source expired")
		}
		select {
		case <-n.done:
			return errors.New("retirement manager stopped")
		default:
		}
		if n.upstream != upstream || upstream.Manager() != m || n.admission != admitted || n.ID() != selfID {
			return errors.New("retirement manager owner changed")
		}
		if !proto.Equal(store.GetCluster(tx, cluster.ID), cluster) {
			return errors.New("retirement native cluster changed")
		}
		current, err := store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		// Every captured manager identity/version/certificate is exact; newly
		// inserted managers and slot aliases also invalidate the projection.
		if !sameRetirementManagerNodes(nodes, current, target.ID) {
			return errors.New("retirement native node projection changed")
		}
		currentMembers, err := m.RaftMembersAtObservation(observed)
		if err != nil {
			return err
		}
		if !sameRetirementMembers(members, currentMembers) {
			return errors.New("retirement native voter projection changed")
		}
		return checkRetirementSurvivors(proof, store.GetNode(tx, target.ID), current, currentMembers, cluster)
	}
	// External signed-source and SDK checks never execute under the store lock.
	if err := proof.Verify(ctx); err != nil {
		return nil, err
	}
	if retained == "" {
		wire, err := protocol.EncodeJSON(pin)
		if err != nil {
			return nil, err
		}
		spec := target.Spec.Copy()
		if spec.Annotations.Labels == nil {
			spec.Annotations.Labels = map[string]string{}
		}
		spec.Annotations.Labels[managerRetirementLabel] = string(wire)
		spec.DesiredRole = api.NodeRoleWorker
		spec.Availability = api.NodeAvailabilityPause
		if err := ociclient.CheckRequestGuard(ctx); err != nil {
			return nil, err
		}
		response, err := m.UpdateNodeAtObservation(ctx, observed, target, &api.UpdateNodeRequest{NodeID: target.ID, NodeVersion: target.Meta.Version.Copy(), Spec: spec}, live)
		if err != nil {
			return nil, err
		}
		if err := proof.Verify(ctx); err != nil {
			return nil, fmt.Errorf("%w: %w", manager.ErrMutationAmbiguous, err)
		}
		return &ManagerRetirementResult{Stage: "demoted", DemotionVersion: response.Node.Meta.Version.Index}, nil
	}
	if target.Role != api.NodeRoleWorker {
		// Native roleManager owns asynchronous voter removal; never resubmit the
		// demotion or create a fresh permission when that work is still pending.
		return &ManagerRetirementResult{Stage: "demoted", DemotionVersion: target.Meta.Version.Index}, nil
	}
	for _, member := range members {
		if member.NodeID == target.ID {
			return nil, errors.New("retired manager remains a current Raft voter")
		}
	}
	if err := ociclient.CheckRequestGuard(ctx); err != nil {
		return nil, err
	}
	if _, err := m.RemoveNodeAtObservation(ctx, observed, target, live); err != nil {
		return nil, err
	}
	if err := proof.Verify(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w", manager.ErrMutationAmbiguous, err)
	}
	return &ManagerRetirementResult{Stage: "removed", DemotionVersion: target.Meta.Version.Index}, nil
}

func managerRetirementNode(node *api.Node, slot, instanceID, region string) bool {
	if node == nil {
		return false
	}
	labels := node.Spec.Annotations.Labels
	return node.Spec.Membership == api.NodeMembershipAccepted && node.Spec.Annotations.Name == slot &&
		labels[LabelInstanceID] == instanceID && labels[LabelRegion] == region && labels[LabelHostRole] == "manager" && labels[LabelExecutionScope] == "platform"
}

func managerRetirementCertificate(node *api.Node, cluster *api.Cluster) error {
	block, _ := pem.Decode(node.Certificate.Certificate)
	if block == nil {
		return errors.New("retirement node certificate missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(cluster.RootCA.CACert) || cert.Subject.CommonName != node.ID ||
		len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != cluster.ID ||
		len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "swarm-manager" {
		return errors.New("retirement node certificate differs from actual current cluster")
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func checkRetirementSurvivors(proof *bootstrapstart.ManagerRetirement, target *api.Node, nodes []*api.Node, members []*api.RaftMember, cluster *api.Cluster) error {
	if target == nil {
		return errors.New("retirement exact target missing")
	}
	expected := proof.Survivors()
	found := map[string]bool{}
	domains := map[string]bool{}
	reachable := 0
	remaining := 0
	for _, member := range members {
		if member.NodeID == target.ID {
			continue
		}
		remaining++
		var actual *api.Node
		for _, node := range nodes {
			if node.ID == member.NodeID {
				actual = node
				break
			}
		}
		matched := false
		for _, survivor := range expected {
			if !managerRetirementNode(actual, survivor.Slot, survivor.InstanceID, proof.OCIRegion()) {
				continue
			}
			if actual.Role != api.NodeRoleManager || actual.Spec.DesiredRole != api.NodeRoleManager || actual.Status.State != api.NodeStatus_READY ||
				member.Status.Reachability != api.RaftMemberStatus_REACHABLE || found[survivor.Slot] || domains[survivor.AvailabilityDomain+"/"+survivor.FaultDomain] {
				return errors.New("surviving native manager is unavailable, duplicated or not an admitted voter")
			}
			if err := managerRetirementCertificate(actual, cluster); err != nil {
				return err
			}
			found[survivor.Slot] = true
			domains[survivor.AvailabilityDomain+"/"+survivor.FaultDomain] = true
			reachable++
			matched = true
			break
		}
		if !matched {
			return errors.New("current Raft voter lacks its exact signed surviving slot and OCI instance")
		}
	}
	if reachable < 2 || reachable < remaining/2+1 {
		return errors.New("manager retirement lacks surviving distinct-domain native quorum")
	}
	for _, node := range nodes {
		if node.ID == target.ID || node.Role != api.NodeRoleManager && node.Spec.DesiredRole != api.NodeRoleManager {
			continue
		}
		actualMember := false
		for _, member := range members {
			if member.NodeID == node.ID {
				actualMember = true
				break
			}
		}
		exactSlot := false
		for _, survivor := range expected {
			if managerRetirementNode(node, survivor.Slot, survivor.InstanceID, proof.OCIRegion()) {
				exactSlot = true
				break
			}
		}
		if !actualMember || !exactSlot {
			return errors.New("unaccounted native manager remains outside the exact verified voter set")
		}
	}

	return nil
}

func sameRetirementManagerNodes(before, after []*api.Node, target string) bool {
	selected := func(node *api.Node) bool {
		return node.ID == target || node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager
	}
	count := 0
	for _, node := range before {
		if !selected(node) {
			continue
		}
		count++
		matched := false
		for _, current := range after {
			if current.ID == node.ID && proto.Equal(current, node) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	currentCount := 0
	for _, node := range after {
		if selected(node) {
			currentCount++
		}
	}
	return count == currentCount
}

func sameRetirementMembers(before, after []*api.RaftMember) bool {
	if len(before) != len(after) {
		return false
	}
	for _, member := range before {
		matched := false
		for _, current := range after {
			if current.RaftID == member.RaftID && proto.Equal(current, member) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func managerRetirementDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}
