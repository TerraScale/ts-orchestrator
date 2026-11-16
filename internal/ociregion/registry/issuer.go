package registry

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/identity"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/TerraScale/ts-orchestrator/internal/region"
)

var ErrIssuer = errors.New("OCIR credential issuer requires current signed authority and recoverable owned resources")

// Issuer creates only the service identity and repository pull credential in
// the same root-signed foundation scope. Credential bytes never enter its KV.
type Issuer struct {
	identity  identity.IdentityClient
	vault     ocivault.VaultsClient
	secrets   ocisecrets.SecretsClient
	artifacts artifacts.ArtifactsClient
	journal   IssuerJournal
	scope     region.VerifiedOCIRIssuer
	guard     func(context.Context) error
	homeWrite func(context.Context) (context.Context, func(), error)
	host      string
}
