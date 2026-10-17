package principal

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
)

// ReaderResult retains actual issuer-observed read IAM; exported DTOs cannot
// construct it or authorize production membership, signing or mutation.
type ReaderResult struct {
	preparation, plan string
	iam               hostadmission.ReaderIAM
	expires           time.Time
}

func (r ReaderResult) IAM() hostadmission.ReaderIAM { return r.iam }
func (r ReaderResult) Validate(v VerifiedPreparation, plan hostadmission.ReaderPlan, now time.Time) error {
	if r.preparation == "" || r.preparation != v.digest || r.plan != plan.SHA256() || r.iam.PlanSHA256 != r.plan ||
		!qualification.ValidReaderIAMIDs(r.iam.DynamicGroupID, r.iam.PolicyID) || !r.expires.Equal(plan.ExpiresAt()) || !now.Before(r.expires) {
		return errors.New("actual reader IAM result differs from finite original signed plan")
	}
	return nil
}

// PrepareReaders consumes an original-signer attenuation of actual SDK host IDs.
// It uses the original issuer, durable exact request intents and finite deadlines.
func (p *Producer) PrepareReaders(ctx context.Context, v VerifiedPreparation, workdir string, proof []byte) (ReaderResult, error) {
	plan, err := hostadmission.VerifyReaderPlan(proof, v.roots, p.now())
	if err != nil || plan.PreparationSHA256() != v.digest {
		return ReaderResult{}, errors.Join(errors.New("original signed reader plan required"), err)
	}
	a, err := p.attempt(ctx, v, workdir, false)
	if err != nil {
		return ReaderResult{}, err
	}
	defer a.store.close()
	if len(a.journal.ReaderProof) == 0 {
		a.journal.ReaderProof, a.journal.ReaderVerifiedAt = bytes.Clone(proof), p.now().UTC()
		if err := a.store.save(a.journal); err != nil {
			return ReaderResult{}, err
		}
	} else {
		original, err := a.readerPlan()
		if err != nil || original.SHA256() != plan.SHA256() {
			return ReaderResult{}, errors.New("reader IAM plan changed after durable original attenuation")
		}
	}
	if err := a.prepareReaders(ctx, false); err != nil {
		return ReaderResult{}, err
	}
	statements, err := a.readerStatements()
	if err != nil {
		return ReaderResult{}, err
	}
	wire, err := json.Marshal(statements, json.Deterministic(true))
	if err != nil {
		return ReaderResult{}, err
	}
	return ReaderResult{preparation: v.digest, plan: plan.SHA256(), expires: plan.ExpiresAt(), iam: hostadmission.ReaderIAM{DynamicGroupID: a.id("reader-group"), PolicyID: a.id("reader-policy"), PolicySHA256: hash(wire), PlanSHA256: plan.SHA256()}}, nil
}

func (a *attempt) readerPlan() (hostadmission.ReaderPlan, error) {
	plan, err := hostadmission.VerifyReaderPlan(a.journal.ReaderProof, a.verified.roots, a.journal.ReaderVerifiedAt)
	if err != nil || plan.PreparationSHA256() != a.verified.digest || a.journal.ReaderVerifiedAt.IsZero() {
		return hostadmission.ReaderPlan{}, errors.Join(errors.New("durable reader plan is missing or differs"), err)
	}
	return plan, nil
}

func (a *attempt) readerStatements() ([]string, error) {
	plan, err := a.readerPlan()
	if err != nil {
		return nil, err
	}
	p := a.verified.preparation
	return qualification.ReaderStatements(a.id("reader-group"), p.Compartment, plan.ExpiresAt()), nil
}

func (a *attempt) readerRule() (string, error) {
	plan, err := a.readerPlan()
	if err != nil {
		return "", err
	}
	var ids []string
	for _, h := range plan.Hosts() {
		ids = append(ids, h.InstanceID)
	}
	rule := qualification.ReaderMatchingRule(ids)
	if rule == "" {
		return "", errors.New("reader group requires four exact distinct instance IDs")
	}
	return rule, nil
}

func (a *attempt) prepareReaders(ctx context.Context, recovery bool) error {
	if len(a.journal.ReaderProof) == 0 {
		return nil
	}
	if recovery {
		pending := false
		for _, name := range []string{"reader-group", "reader-policy"} {
			if op := a.journal.Operations[name]; op != nil && op.ID == "" && !op.DeleteIntent {
				pending = true
			}
		}
		if !pending {
			return nil
		}
	}
	plan, err := a.readerPlan()
	if err != nil {
		return err
	}
	if !a.producer.now().Before(plan.ExpiresAt()) {
		return errors.New("original reader IAM creation interval expired")
	}
	p := a.verified.preparation
	should := func(name string) bool { return !recovery || a.journal.Operations[name] != nil && a.id(name) == "" }
	if should("reader-group") {
		rule, err := a.readerRule()
		if err != nil {
			return err
		}
		details := identity.CreateDynamicGroupDetails{CompartmentId: new(p.Tenancy), Name: new(p.GroupName + "-readers"), Description: new(a.description()), MatchingRule: new(rule)}
		_, err = a.create(ctx, "reader-group", identity.CreateDynamicGroupRequest{CreateDynamicGroupDetails: details}, "/dynamicGroups", func(token string) (string, error) {
			r, err := a.client.CreateDynamicGroup(ociclient.RequestContext(ctx), identity.CreateDynamicGroupRequest{CreateDynamicGroupDetails: details, OpcRetryToken: new(token), OpcRequestId: new(token)})
			return value(r.Id), err
		})
		if err != nil {
			return err
		}
	}
	if should("reader-policy") {
		statements, err := a.readerStatements()
		if err != nil || !validID("reader-group", a.id("reader-group")) {
			return errors.Join(errors.New("reader policy requires actual finite dynamic group"), err)
		}
		details := identity.CreatePolicyDetails{CompartmentId: new(p.Tenancy), Name: new(p.PolicyName + "-readers"), Description: new(a.description()), Statements: slices.Clone(statements)}
		_, err = a.create(ctx, "reader-policy", identity.CreatePolicyRequest{CreatePolicyDetails: details}, "/policies", func(token string) (string, error) {
			r, err := a.client.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{CreatePolicyDetails: details, OpcRetryToken: new(token), OpcRequestId: new(token)})
			return value(r.Id), err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// CleanupReaders revokes read authority before the temporary issuer principal is
// removed. Cloud cleanup and retained-image supervision keep their own deadlines.
func (p *Producer) CleanupReaders(ctx context.Context, v VerifiedPreparation, workdir string) error {
	a, err := p.attempt(ctx, v, workdir, true)
	if err != nil {
		return err
	}
	defer a.store.close()
	result := a.prepareReaders(ctx, true)
	for _, name := range []string{"reader-policy", "reader-group"} {
		op := a.journal.Operations[name]
		if op == nil || op.Deleted {
			continue
		}
		if op.ID == "" {
			result = errors.Join(result, errors.New("unresolved reader IAM create requires authenticated exact-ID recovery"))
			continue
		}
		result = errors.Join(result, a.revoke(ctx, name, op))
	}
	return result
}
