package bootstrapmaterial

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/jwt/v2"
)

// IssueFunctionCredentials retains the generation's account signer inside the
// controller. The caller reads the current durable account claim and fences
// publication against concurrent claim or function-intent changes.
func (issuer *ControllerIssuer) IssueFunctionCredentials(admitted release.VerifiedFunction, accountJWT string, existing []byte) ([]byte, functions.WorkerBrokerIdentity, error) {
	if issuer == nil || !admitted.Valid() {
		return nil, functions.WorkerBrokerIdentity{}, errors.New("function issuance requires a current admitted release and controller generation")
	}
	claim := admitted.Claim()
	account, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil || account.Subject != issuer.generation.CellAccount || account.Issuer != issuer.generation.Operator ||
		claim.Environment != issuer.generation.Environment || claim.Cell != string(issuer.generation.Cell) {
		return nil, functions.WorkerBrokerIdentity{}, errors.New("function release or broker account differs from the controller generation")
	}
	return functions.IssueWorkerCredentials(admitted, issuer.generation.CellAccount, accountJWT, issuer.signer, existing)
}
