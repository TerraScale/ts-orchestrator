package manager

import (
	"context"
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// Automatic continuously reconciles the account from GRU authority and its
// authenticated foundation record. Missing foundation or Vault state is retried.
// credential must resolve the admitted GRU foundation, never an observed peer.
func Automatic(fencer authority.Fencer, credential func(context.Context) (vaultsecret.Ref, error),
	logf func(string, ...any),
) Loop {
	return Loop{Authority: fencer, Desired: GRU(), Logf: logf, Token: func(ctx context.Context) ([]byte, error) {
		if credential == nil {
			return nil, errors.New("NetBird management pending GRU foundation")
		}
		ref, err := credential(ctx)
		if err != nil {
			return nil, errors.New("NetBird management pending GRU foundation credential")
		}
		if ref.Name != "gru-1-netbird-admin-pat" || !strings.HasPrefix(ref.Vault, "ocid1.vault.oc1.sa-saopaulo-1.") {
			return nil, errors.New("NetBird management credential does not belong to the GRU foundation")
		}
		values, err := vaultsecret.ReadCurrentRefs(ctx, map[string]vaultsecret.Ref{"NETBIRD_ADMIN_PAT": ref})
		if err != nil {
			return nil, errors.New("NetBird management pending GRU Vault credential")
		}
		token := []byte(values["NETBIRD_ADMIN_PAT"].Value())
		if !netbird.ValidAdminPAT(token) {
			clear(token)
			return nil, errors.New("NetBird management Vault credential has an invalid shape")
		}
		return token, nil
	}}
}
