package natscell

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestReadControllerAccountCopiesInstalledOperatorAndCurrentNativeJWT(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	region := newTestRegion(t, dir, "gru", LeafTopology{Hub: "gru"})
	signer, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Wipe()
	signingKey, _ := signer.PublicKey()
	operator := jwt.NewOperatorClaims(region.operatorID)
	operator.SystemAccount = region.systemID
	operator.SigningKeys = jwt.StringList{signingKey}
	operator.OperatorServiceURLs = jwt.StringList{"tls://127.0.0.1:4222"}
	operator.Tags = jwt.TagList{"installed"}
	operatorJWT, err := operator.Encode(region.operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(region.cfg.Embedded.OperatorJWTFile, []byte(operatorJWT), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(ctx, region.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	view, err := runtime.ReadControllerAccount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.Account != region.cellID || view.JWT != runtime.InitialCellJWT() || view.Operator.Subject != region.operatorID {
		t.Fatal("native account view differs from the installed regional account/operator")
	}
	view.Operator.SigningKeys[0] = "altered"
	view.Operator.OperatorServiceURLs[0] = "altered"
	view.Operator.Tags[0] = "altered"
	held, err := runtime.ReadControllerAccount(ctx)
	if err != nil || held.Operator.SigningKeys[0] != signingKey ||
		held.Operator.OperatorServiceURLs[0] != "tls://127.0.0.1:4222" || held.Operator.Tags[0] != "installed" {
		t.Fatal("returned operator aliases installed mutable slices", err)
	}
	claim, err := jwt.DecodeAccountClaims(held.JWT)
	if err != nil {
		t.Fatal(err)
	}
	// JWT encoding stamps seconds; resolver replacements must advance them.
	for time.Now().Unix() <= claim.IssuedAt {
		select {
		case <-ctx.Done():
			t.Fatal("account replacement timestamp did not advance")
		case <-time.After(10 * time.Millisecond):
		}
	}
	claim.Name = "native successor"
	replacement, err := claim.Encode(region.operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.ApplyCellClaim(ctx, 1, replacement); err != nil {
		t.Fatal(err)
	}
	current, err := runtime.ReadControllerAccount(ctx)
	if err != nil || current.JWT != replacement || current.Account != held.Account || current.Operator.Subject != held.Operator.Subject {
		t.Fatal("account view did not read the actual applied resolver successor", err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := runtime.ReadControllerAccount(canceled); err == nil {
		t.Fatal("native account view ignored cancellation")
	}

	t.Run("transport-only runtime", func(t *testing.T) {
		if _, err := (*Runtime)(nil).ReadControllerAccount(t.Context()); err == nil {
			t.Fatal("nil runtime provided native account state")
		}
		if _, err := new(Runtime).ReadControllerAccount(t.Context()); err == nil {
			t.Fatal("transport-only runtime provided native account state")
		}
	})
}
