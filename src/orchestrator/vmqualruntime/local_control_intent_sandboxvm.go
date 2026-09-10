//go:build sandboxvm

package vmqualruntime

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/url"
	"path/filepath"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/candidateplan"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type LocalQualificationControlIntentRequest struct {
	IssuedAt      time.Time                            `json:"issuedAt"`
	ExpiresAt     time.Time                            `json:"expiresAt"`
	Regions       []bootstrap.ControlRegionBinding     `json:"regions"`
	StoreName     string                               `json:"storeName"`
	StoreReader   nodeauthority.ReaderConfig           `json:"storeReader"`
	Manifest      hostmanifest.HostManifest            `json:"manifest"`
	CandidatePlan candidateplan.Plan                   `json:"candidatePlan"`
	Actions       []bootstrap.ControlRuntimeActionPlan `json:"actions"`
}

func BuildLocalQualificationControlPayload(network vmnet.NetworkPlan, run vmcontrolseed.RunDeclaration, artifacts []vmimage.GuestArtifact, request LocalQualificationControlIntentRequest) (jsontext.Value, error) {
	if network.Validate() != nil || network.RunID == "" || run.Version != 1 || len(run.Hosts) != 6 || len(artifacts) != 3 || request.IssuedAt.IsZero() || request.ExpiresAt.Before(request.IssuedAt) || request.ExpiresAt.Sub(request.IssuedAt) > 24*time.Hour || len(request.Actions) == 0 || len(request.Regions) != 3 || request.StoreName == "" || filepath.Base(request.StoreName) != request.StoreName {
		return nil, errors.New("vmqual control intent: invalid bounded request")
	}
	seen := map[string]bool{}
	guests := map[string]vmnet.GuestNetwork{}
	for _, region := range network.Regions {
		if region.Code == "IAD" {
			continue
		}
		if len(region.Guests) != 2 {
			return nil, errors.New("vmqual control intent: launch region requires two guests")
		}
		for _, guest := range region.Guests {
			guests[guest.ID] = guest
		}
	}
	for _, host := range run.Hosts {
		if host.Generation != 1 || seen[host.HostID] || guests[host.HostID].ID == "" || host.Regional.Connection.PublicNKey == "" || host.Regional.Connection.TLS.CertificateSHA256 == "" {
			return nil, errors.New("vmqual control intent: run host mismatch")
		}
		seen[host.HostID] = true
	}
	if len(seen) != 6 {
		return nil, errors.New("vmqual control intent: six unique launch hosts required")
	}
	regionNames := []string{"gru", "sfo", "fra"}
	for i, name := range regionNames {
		if request.Regions[i].Code != name || len(request.Regions[i].MemberIDs) != 2 || !slices.Contains(request.Regions[i].MemberIDs, "ocid1.instance."+name+"-member-1") || !slices.Contains(request.Regions[i].MemberIDs, "ocid1.instance."+name+"-member-2") {
			return nil, errors.New("vmqual control intent: region binding mismatch")
		}
	}
	gru := guests["gru-member-1"]
	parsed, err := url.Parse(request.StoreReader.Endpoint)
	if err != nil || parsed.Hostname() != gru.Address || request.StoreReader.ServerName != gru.ID || request.StoreReader.NKeySeedFile != "" || request.StoreReader.CAFile != "" || request.StoreReader.CertificateFile != "" || request.StoreReader.KeyFile != "" {
		return nil, errors.New("vmqual control intent: source store reader mismatch")
	}
	members := make([]qualificationControlMemberDeclaration, 0, 6)
	for _, name := range []string{"gru", "sfo", "fra"} {
		for i := 1; i <= 2; i++ {
			host := name + "-member-" + string(rune('0'+i))
			members = append(members, qualificationControlMemberDeclaration{Member: bootstrap.ControlRuntimeMember{MemberID: "ocid1.instance." + host, HostID: host, ServerName: host, Instance: host, Region: name, Store: request.StoreName}, Generation: 1})
		}
	}
	stores := map[string]qualificationControlStoreDeclaration{request.StoreName: {Reader: request.StoreReader, Files: map[string]qualificationControlFile{}}}
	payload := qualificationControlPayload{Version: 1, RunID: network.RunID, IssuedAt: request.IssuedAt, ExpiresAt: request.ExpiresAt, Artifacts: slices.Clone(artifacts), Stores: stores, Members: members, Regions: slices.Clone(request.Regions), CandidatePlan: &request.CandidatePlan}
	for _, action := range request.Actions {
		if action.Region != "gru" && action.Region != "sfo" && action.Region != "fra" {
			return nil, errors.New("vmqual control intent: action region mismatch")
		}
		for _, check := range action.Checks {
			if check.AuthorityTerm != 0 || check.AuthorityCandidateID != "" || check.AuthorityLeaseID != "" {
				return nil, errors.New("vmqual control intent: live authority fields are not intent")
			}
		}
		payload.Actions = append(payload.Actions, qualificationControlActionDeclaration{Plan: action})
	}
	if payload.CandidatePlan.SourceNodeID != "gru-member-1" || len(payload.CandidatePlan.Candidates) != 2 {
		return nil, errors.New("vmqual control intent: candidate source or count mismatch")
	}
	return json.Marshal(payload)
}
