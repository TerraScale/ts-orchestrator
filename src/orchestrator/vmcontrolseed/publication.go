package vmcontrolseed

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
)

const PublicationJournalNKeyPath = Directory + "/publication/provider-journal.seed"
const PublicationCertificatePath = Directory + "/publication/client.pem"
const PublicationPrivateKeyPath = Directory + "/publication/client.key"
const PublicationRequestPath = Directory + "/publication/request.json"
const PublicationStatePath = "/var/lib/terrascale/orchestrator/publication"
const PublicationQualificationKeyPath = Directory + "/publication/qualification.key"

// PreliminaryPublicationDeclaration explicitly enables source-owned OCI
// publication. The only copied provider key is an explicitly declared fixture
// transport identity; production uses the machine's real instance principal.
type PreliminaryPublicationDeclaration struct {
	Identity                ociinstance.Config `json:"identity"`
	qualificationPrivateKey []byte
}

func (d *PreliminaryPublicationDeclaration) Clear() {
	if d != nil {
		clear(d.qualificationPrivateKey)
	}
}
func (d PreliminaryPublicationDeclaration) Validate() error {
	if err := ociinstance.ValidateConfig(d.Identity); err != nil {
		return err
	}
	if q := d.Identity.Qualification; q != nil {
		if q.ClientPrivateKeyFile != PublicationQualificationKeyPath {
			return errors.New("vmcontrolseed: publication qualification key path differs")
		}
		if _, err := tls.X509KeyPair([]byte(q.ClientCertificatePEM), d.qualificationPrivateKey); err != nil {
			return errors.New("vmcontrolseed: publication qualification private identity differs")
		}
	} else if len(d.qualificationPrivateKey) != 0 {
		return errors.New("vmcontrolseed: undeclared qualification identity")
	}
	return nil
}

// LoadPreliminaryPublicationDeclaration reads a protected explicit opt-in. The
// JSON is canonical; its qualification key path denotes a runner-owned input,
// rewritten to a fixed source-private guest path only after capture/validation.
func LoadPreliminaryPublicationDeclaration(path string) (*PreliminaryPublicationDeclaration, error) {
	bad := errors.New("vmcontrolseed: invalid protected publication declaration")
	raw, err := bootstrapcredentials.ReadFile(path, true, 64<<10)
	if err != nil {
		return nil, bad
	}
	var d PreliminaryPublicationDeclaration
	if json.Unmarshal(raw, &d) != nil {
		return nil, bad
	}
	canonical, err := json.Marshal(d)
	if err != nil || !bytes.Equal(canonical, raw) || ociinstance.ValidateConfig(d.Identity) != nil {
		return nil, bad
	}
	if q := d.Identity.Qualification; q != nil {
		private, err := bootstrapcredentials.ReadFile(q.ClientPrivateKeyFile, true, 64<<10)
		if err != nil {
			return nil, bad
		}
		d.qualificationPrivateKey = private
		q.ClientPrivateKeyFile = PublicationQualificationKeyPath
	}
	if err := d.Validate(); err != nil {
		d.Clear()
		return nil, bad
	}
	return &d, nil
}
