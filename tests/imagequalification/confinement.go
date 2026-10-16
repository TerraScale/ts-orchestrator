package imagequalification

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

// ConfinementScope describes independently approved resources for observation.
// Only exact durable resource IDs can refine an existing run after a restart.
// Returning a scope grants no execution privilege.
func (p Prepared) ConfinementScope(journalPath string) (confinement.Scope, error) {
	if err := p.approval.validate(); err != nil {
		return confinement.Scope{}, err
	}
	if p.approvalSHA256 == "" || hashBytes(p.approvalWire) != p.approvalSHA256 {
		return confinement.Scope{}, errors.New("sealed approval is absent")
	}
	c := cloud{prepared: p}
	j, err := c.load(journalPath)
	if err != nil {
		return confinement.Scope{}, err
	}
	return p.confinementScope(j), nil
}

func (p Prepared) confinementScope(j journal) confinement.Scope {
	a := p.approval
	s := confinement.Scope{ApprovalSHA256: p.approvalSHA256, RunID: a.RunID, Tenancy: a.Tenancy, IAMRegion: a.IAMRegion, Principal: a.Principal, Group: a.Group, PolicyID: a.PolicyID, Compartment: a.Compartment, Subnet: a.Subnet, Namespace: a.Namespace, Bucket: a.Bucket, Object: j.Object, RunnerCIDR: a.RunnerCIDR, PeerCIDR: a.PeerCIDR, VCNCIDR: a.VCNCIDR, PolicyStatements: slices.Clone(a.PolicyStatements), ProductionDynamicGroups: slices.Clone(a.ProductionDynamicGroups), ExpiresAt: p.expires, CleanupUntil: a.CleanupUntil, ExistingHosts: map[string]string{}}
	c := cloud{prepared: p}
	for _, host := range a.Hosts {
		s.HostNames = append(s.HostNames, c.name(host.Name))
		if id := j.Hosts[host.Name]; id != "" {
			s.ExistingHosts[id] = c.name(host.Name)
		}
	}
	return s
}

func newConfinedCloud(ctx context.Context, p Prepared, verified confinement.Verified, path string) (*cloud, error) {
	scope, err := p.ConfinementScope(path)
	if err != nil {
		return nil, err
	}
	want, err := json.Marshal(scope, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	observed, err := json.Marshal(verified.Scope(), json.Deterministic(true))
	if err != nil || !bytes.Equal(want, observed) || len(verified.Evidence()) == 0 || hashBytes(verified.Evidence()) != verified.EvidenceSHA256() {
		return nil, errors.New("actual confinement does not match this independently approved run")
	}
	if err := verified.Revalidate(ctx, scope); err != nil {
		return nil, err
	}
	c, err := newCloud(p, verified.Factory(), "")
	if err != nil {
		return nil, err
	}
	inspector, err := newCloud(p, verified.Factory(), "")
	if err != nil {
		return nil, err
	}
	for _, base := range []*common.BaseClient{&inspector.compute.BaseClient, &inspector.block.BaseClient} {
		previous := base.Interceptor
		base.Interceptor = func(request *http.Request) error {
			if previous != nil {
				if err := previous(request); err != nil {
					return err
				}
			}
			return c.check(request.Context(), true)
		}
		ociclient.ConfigureRequestCancellation(base)
	}
	guard := func(base *common.BaseClient) {
		previous := base.Interceptor
		base.Interceptor = func(request *http.Request) error {
			if previous != nil {
				if err := previous(request); err != nil {
					return err
				}
			}
			cleanup := request.Method == http.MethodGet || request.Method == http.MethodHead || request.Method == http.MethodDelete
			if err := c.check(request.Context(), cleanup); err != nil {
				return err
			}
			j, err := c.load(path)
			if err != nil {
				return err
			}
			if err := verified.Revalidate(request.Context(), p.confinementScope(j)); err != nil {
				return err
			}
			if err := inspector.validateHostBounds(request.Context(), j); err != nil {
				return err
			}
			return c.check(request.Context(), cleanup)
		}
		ociclient.ConfigureRequestCancellation(base)
	}
	guard(&c.compute.BaseClient)
	guard(&c.objects.BaseClient)
	guard(&c.network.BaseClient)
	guard(&c.block.BaseClient)
	work, err := verified.Factory().WorkRequests()
	if err != nil {
		return nil, err
	}
	guard(&work.BaseClient)
	c.uploader = imageimport.NewClientFromSDK(c.compute, c.objects, work)
	return c, nil
}
