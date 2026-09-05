//go:build sandboxvm

package vmqualruntime

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

// Command identities enroll planned regional candidates. Their presence grants
// no authority: the guest receiver still reads the actual regional lease.
func (authority *qualificationNATSAuthority) issueCommandIdentities(region vmnet.RegionNetwork) error {
	for index, guest := range region.Guests {
		if index == 3 {
			break
		}
		candidate := strings.ToLower(string(region.Code)) + "-controller-" + guest.ID
		identity, err := newQualificationMembershipIdentity()
		if err != nil {
			return err
		}
		authority.commandSigners[candidate] = identity
	}
	return nil
}

func (authority *qualificationNATSAuthority) commandTrust(plan vmnet.NetworkPlan, code vmnet.RegionCode) ([]vmimage.TSNodeCommandTrust, error) {
	for _, region := range plan.Regions {
		if region.Code != code {
			continue
		}
		trust := make([]vmimage.TSNodeCommandTrust, 0, 3)
		for index, guest := range region.Guests {
			if index == 3 {
				break
			}
			candidate := strings.ToLower(string(region.Code)) + "-controller-" + guest.ID
			identity := authority.commandSigners[candidate]
			if identity == nil {
				return nil, errors.New("vmqual: regional command signing identity missing")
			}
			der, err := base64.StdEncoding.DecodeString(identity.PublicKey)
			if err != nil {
				return nil, err
			}
			trust = append(trust, vmimage.TSNodeCommandTrust{CandidateID: candidate, PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})})
		}
		return trust, nil
	}
	return nil, errors.New("vmqual: command trust Region undeclared")
}
