package bootstrapmaterial

import (
	"errors"
	"fmt"
	"slices"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// CheckControllerCredentials binds an offline-issued controller user to its
// cell and slot and requires exactly the controller role's grants.
func CheckControllerCredentials(creds []byte, cell, slot, account string) error {
	if err := natscell.ValidateBrokerControllerCredentialBytes(creds, cell, slot); err != nil {
		return err
	}
	raw, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return err
	}
	if !nkeys.IsValidPublicAccountKey(account) || claim.Issuer != account ||
		claim.IssuerAccount != "" && claim.IssuerAccount != account ||
		claim.Expires == 0 || claim.Expires <= claim.IssuedAt || claim.NotBefore != 0 ||
		!slices.Contains(claim.Sub.Allow, protocol.ObservabilityGrant(cell)) {
		return errors.New("controller credentials need the cell account signature, finite lifetime and local observability subscription")
	}
	allowed := natscell.ControllerPublishes(cell)
	allowed.Add(natscell.GlobalControllerPublishes()...)
	for _, grant := range claim.Pub.Allow {
		if !slices.Contains(allowed, grant) {
			return fmt.Errorf("controller credentials have unscoped publish %q", grant)
		}
	}
	for _, grant := range natscell.ControllerPublishes(cell) {
		if !slices.Contains(claim.Pub.Allow, grant) {
			return fmt.Errorf("controller credentials lack publish %q", grant)
		}
	}
	return nil
}
