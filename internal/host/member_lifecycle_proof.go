package host

import (
	"context"
	"errors"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
)

// readManagedServingProof uses the same native runner process binding as the
// basic status reader. The peer incarnation is checked later against the
// controller's signed roster, which is not carried in the host desired.
func readManagedServingProof(ctx context.Context, runner Runner, desired Desired, socket string, observed MemberStatus) (*memberstatus.ServingProof, error) {
	if !observed.Serving {
		return nil, nil
	}
	client, err := managedMemberClient(runner, desired, socket)
	if err != nil {
		return nil, err
	}
	status, err := client.Status(ctx)
	if err != nil {
		return nil, err
	}
	if status.Process.PID != observed.Process.PID || status.Process.StartNonce != observed.Process.StartNonce {
		return nil, memberstatus.ErrStaleBinding
	}
	if !status.Serving {
		return nil, nil
	}
	proof, err := client.ServingProofForPeer(ctx, status, desired.ManagedMember.Runtime.ReplicationPeerMemberID)
	if errors.Is(err, memberstatus.ErrNotServing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &proof, nil
}

func managedMemberClient(runner Runner, desired Desired, socket string) (*memberstatus.Client, error) {
	p, ok := runner.(*processRunner)
	if !ok || p == nil || desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil {
		return nil, errors.New("serving proof requires a native managed member")
	}
	launch := desired.ManagedMember
	scope := launch.Member.Scope
	authority := launch.Authority
	return memberstatus.NewClient(socket,
		memberstatus.Scope{
			ClusterID: scope.ClusterID, TenantID: scope.TenantID, DatabaseID: scope.DatabaseID,
			ShardID: scope.ShardID, MemberID: scope.MemberID, Incarnation: scope.Incarnation,
		},
		memberstatus.Authority{
			Epoch: authority.Epoch, ConfigurationID: authority.ConfigurationID,
			CertificateSHA256: authority.CertificateSHA256, TLSLeafSHA256: authority.TLSLeafSHA256,
		},
		func(check context.Context) (memberstatus.ProcessObservation, error) {
			pid, start, cgroup, err := observeMemberProcess(check, p, desired.Role)
			return memberstatus.ProcessObservation{
				PID: pid, UID: p.identity.UID, GID: p.identity.GID, KernelStart: start, Cgroup: cgroup,
			}, err
		})
}
