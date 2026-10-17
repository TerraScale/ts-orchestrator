package natscell

import (
	"context"
	"errors"
	"slices"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
)

type ControllerAccountView struct {
	Account  string
	JWT      string
	Operator jwt.OperatorClaims
}

// ReadControllerAccount exposes only the actual regional account and a copy of
// the installed public operator. No caller selects an account or private key.
func (r *Runtime) ReadControllerAccount(ctx context.Context) (ControllerAccountView, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.server == nil || !r.server.Running() ||
		r.resolver == nil || r.operator == nil {
		return ControllerAccountView{}, errors.New("native controller account view is unavailable")
	}
	account := r.resolver.cell
	raw, err := r.resolver.Fetch(account)
	if err != nil {
		return ControllerAccountView{}, err
	}
	claim, err := jwt.DecodeAccountClaims(raw)
	if err != nil || claim.Subject != account || !r.operator.DidSign(claim) {
		return ControllerAccountView{}, errors.New("regional account differs from the installed public operator")
	}
	actual, err := r.server.Accountz(&server.AccountzOptions{Account: account})
	if err != nil {
		return ControllerAccountView{}, err
	}
	if actual.Account == nil || actual.Account.Jwt != raw {
		return ControllerAccountView{}, errors.New("regional account JWT lacks exact native readback")
	}
	current, err := r.resolver.Fetch(account)
	if err != nil || current != raw || ctx.Err() != nil || !r.server.Running() {
		return ControllerAccountView{}, errors.New("native controller account changed during observation")
	}
	operator := *r.operator
	operator.SigningKeys = slices.Clone(operator.SigningKeys)
	operator.OperatorServiceURLs = slices.Clone(operator.OperatorServiceURLs)
	operator.Tags = slices.Clone(operator.Tags)
	return ControllerAccountView{Account: account, JWT: raw, Operator: operator}, nil
}
