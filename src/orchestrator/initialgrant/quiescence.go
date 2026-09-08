package initialgrant

import (
	"context"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

// QuiescenceConfig admits credentials that are absent from the ordinary
// initial broker auth map. Only a verified final-cut request activates them.
// RequestFile is root-owned public plan bytes; StateDir holds service-owned
// durable intent and observed evidence, which the trusted host must verify.
type QuiescenceConfig struct {
	RequestFile string `json:"requestFile"`
	StateDir string `json:"stateDir"`
	Regional Connection `json:"regional"`
	Global Connection `json:"global"`
}

func (c Config) validateQuiescence() error {
	q := c.SourceQuiescence
	if q == nil { return nil }
	bad := errors.New("initialgrant: invalid finite source quiescence admission")
	if c.Role != "seed" || c.Global == nil || c.StorageTransition == (controltransition.Delivery{}) || !cleanPath(q.RequestFile) || !cleanPath(q.StateDir) || q.StateDir == "/" || !q.Regional.valid() || !q.Global.valid() { return bad }
	paths := []string{c.Broker.StoreDir, c.StorageTransition.PlanFile, c.StorageTransition.ReceiptPrivateKeyFile, q.RequestFile}
	if c.PreliminaryCapture != nil {
		paths = append(paths, c.PreliminaryCapture.RequestFile, c.PreliminaryCapture.OutputDir)
		if c.PreliminaryCapture.Publication != nil { paths = append(paths, c.PreliminaryCapture.Publication.RequestFile, c.PreliminaryCapture.Publication.StateDir) }
	}
	for _, path := range paths { if hostmanifest.PathsOverlap(path, q.StateDir) { return bad } }
	for _, path := range paths[:len(paths)-1] {
		if path != q.RequestFile && hostmanifest.PathsOverlap(path, q.RequestFile) { return bad }
	}
	return nil
}

func ReadQuiescenceRequest(path string) ([]byte, error) { return readRootRequest(path, controltransition.MaximumBytes) }

// VerifyQuiescenceRequest binds the original signed source launch and owner;
// a plan cannot substitute its own verifier or a different retained store.
func (a *Admission) VerifyQuiescenceRequest(ctx context.Context, raw []byte) (controltransition.VerifiedPlan, error) {
	var zero controltransition.VerifiedPlan
	if err := a.Check(ctx); err != nil { return zero, err }
	if a.proof == nil || a.proof.config.SourceQuiescence == nil { return zero, errors.New("initialgrant: source quiescence not admitted") }
	v, err := controltransition.VerifyPlan(a.proof.public, raw)
	if err != nil { return zero, err }
	p, err := v.Plan()
	if err != nil { return zero, err }
	i, c := a.proof.identity, a.proof.config
	if err := v.Check(time.Now()); err != nil { return zero, err }
	if p.TransitionID != c.StorageTransition.TransitionID || p.Source.NodeID != i.NodeID || p.Source.BootstrapGrantSHA256 != i.GrantSHA256 || p.Source.InitialManifestSHA256 != i.ManifestSHA256 || p.Source.LaunchSHA256 != i.LaunchSHA256 || p.Source.StoreScopeSHA256 != i.StoreScopeSHA256 || p.Source.ProfileSHA256 != c.ProfileSHA256 || p.Source.StoreDir != c.Broker.StoreDir || p.Source.ServerName != c.Broker.ServerName || p.IssuedAt.Before(i.IssuedAt) || p.ExpiresAt.After(i.ExpiresAt) || len(p.Accounts) != 2 { return zero, errors.New("initialgrant: quiescence request differs from original source") }
	accounts := map[string]string{"regional": c.Regional.Account, "global": c.Global.Account}
	for _, account := range p.Accounts { if accounts[account.Role] != account.SourceName { return zero, errors.New("initialgrant: quiescence account differs") }; delete(accounts, account.Role) }
	if len(accounts) != 0 { return zero, errors.New("initialgrant: incomplete quiescence accounts") }
	return v, nil
}
