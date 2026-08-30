package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type TriggerDisposition uint8

const (
	TriggerUnspecified TriggerDisposition = iota
	TriggerIgnored
	TriggerHeld
	TriggerDispatch
)

type TriggerReason uint8

const (
	ReasonUnspecified TriggerReason = iota
	ReasonFeatureValidation
	ReasonDevelopValidation
	ReasonTrustedArtifactBuild
	ReasonMetadataOnly
	ReasonUnsupportedReference
	ReasonPolicyDenied
	ReasonProtectedReferenceDeleted
)

type JobKind uint8

const (
	JobUnspecified JobKind = iota
	JobProductValidation
	JobTrustedBuild
)

type TrustZone uint8

const (
	TrustUnspecified TrustZone = iota
	TrustUntrustedProduct
	TrustTrustedBuild
)

type RunnerCapability uint8

const (
	CapabilityCompile RunnerCapability = iota + 1
	CapabilityTest
	CapabilitySign
)

type ResolvedJobRevision struct {
	Repository, Commit, Tree string
	SignatureVerified        bool
}
type JobRequest struct {
	Pipeline, Job, Idempotency, Tree             string
	Kind                                         JobKind
	Generation                                   int64
	Attempt, MaxAttempts                         int
	Trust                                        TrustZone
	Capabilities                                 []RunnerCapability
	MinimumRunnerSequence, MaximumRunnerSequence int64
	RetryAuthorized                              bool
}
type TriggerPlan struct {
	Envelope            *WebhookEnvelope
	Disposition         TriggerDisposition
	Reason              TriggerReason
	JobKind             JobKind
	TrustZone           TrustZone
	Capabilities        []RunnerCapability
	MayPublishArtifacts bool
}

func PlanTrigger(e *WebhookEnvelope) *TriggerPlan {
	p := &TriggerPlan{Envelope: e}
	if e == nil {
		p.Disposition = TriggerHeld
		p.Reason = ReasonPolicyDenied
		return p
	}
	switch e.Kind {
	case WebhookPush:
		return planPush(p)
	case WebhookPullRequest:
		return planPR(p)
	default:
		p.Disposition = TriggerHeld
		p.Reason = ReasonPolicyDenied
		return p
	}
}
func planPush(p *TriggerPlan) *TriggerPlan {
	e := p.Envelope
	if e.IsDeletion {
		if e.SourceRef == "refs/heads/develop" || e.SourceRef == "refs/heads/main" {
			p.Disposition = TriggerHeld
			p.Reason = ReasonProtectedReferenceDeleted
		} else {
			p.Disposition = TriggerIgnored
			p.Reason = ReasonUnsupportedReference
		}
		return p
	}
	switch e.SourceRef {
	case "refs/heads/develop":
		p.Disposition = TriggerDispatch
		p.Reason = ReasonDevelopValidation
		p.JobKind = JobProductValidation
		p.TrustZone = TrustUntrustedProduct
		p.Capabilities = []RunnerCapability{CapabilityCompile, CapabilityTest}
	case "refs/heads/main":
		p.Disposition = TriggerHeld
		p.Reason = ReasonPolicyDenied
	default:
		p.Disposition = TriggerIgnored
		p.Reason = ReasonUnsupportedReference
	}
	return p
}
func planPR(p *TriggerPlan) *TriggerPlan {
	e := p.Envelope
	if e.Action != "opened" && e.Action != "reopened" && e.Action != "synchronized" {
		p.Disposition = TriggerIgnored
		p.Reason = ReasonMetadataOnly
		return p
	}
	if e.TargetRef == "develop" {
		p.Disposition = TriggerDispatch
		p.Reason = ReasonFeatureValidation
		p.JobKind = JobProductValidation
		p.TrustZone = TrustUntrustedProduct
		p.Capabilities = []RunnerCapability{CapabilityCompile, CapabilityTest}
		return p
	}
	if e.TargetRef == "main" {
		if !e.IsFork() && e.SourceRef == "develop" {
			p.Disposition = TriggerDispatch
			p.Reason = ReasonTrustedArtifactBuild
			p.JobKind = JobTrustedBuild
			p.TrustZone = TrustTrustedBuild
			p.Capabilities = []RunnerCapability{CapabilityCompile, CapabilityTest, CapabilitySign}
			p.MayPublishArtifacts = true
		} else {
			p.Disposition = TriggerHeld
			p.Reason = ReasonPolicyDenied
		}
		return p
	}
	p.Disposition = TriggerIgnored
	p.Reason = ReasonUnsupportedReference
	return p
}
func (p *TriggerPlan) CreateJob(revision ResolvedJobRevision, generation, minRunner, maxRunner int64) (JobRequest, error) {
	if p == nil || p.Disposition != TriggerDispatch {
		return JobRequest{}, errors.New("non-dispatch trigger cannot create work")
	}
	e := p.Envelope
	if revision.Repository != e.Repository || !strings.EqualFold(revision.Commit, e.Revision) || !objectID(revision.Tree) || allZero(revision.Tree) {
		return JobRequest{}, errors.New("resolved source does not match signed revision")
	}
	if p.JobKind == JobTrustedBuild && !revision.SignatureVerified {
		return JobRequest{}, errors.New("trusted build requires verified source signature")
	}
	if generation <= 0 || minRunner <= 0 || maxRunner < minRunner {
		return JobRequest{}, errors.New("invalid generation or runner bounds")
	}
	d := sha256.Sum256([]byte(e.DedupeKey() + "\n" + fmt.Sprint(p.JobKind)))
	identity := hex.EncodeToString(d[:])
	caps := append([]RunnerCapability(nil), p.Capabilities...)
	return JobRequest{Pipeline: "forgejo-" + identity[:24], Job: "ci-" + identity[:32], Idempotency: "forgejo-" + identity, Tree: strings.ToLower(revision.Tree), Kind: p.JobKind, Generation: generation, Attempt: 1, MaxAttempts: 3, Trust: p.TrustZone, Capabilities: caps, MinimumRunnerSequence: minRunner, MaximumRunnerSequence: maxRunner}, nil
}

type SourceGraphConfig struct{ Repositories []string }

func LoadSourceGraphConfig(path string, root SourceConfig) (SourceGraphConfig, error) {
	if strings.TrimSpace(path) == "" {
		if root.Repository == "" {
			return SourceGraphConfig{}, nil
		}
		return SourceGraphConfig{Repositories: []string{root.Repository}}, nil
	}
	b, e := readBoundedFile(path, 64<<10)
	if e != nil {
		return SourceGraphConfig{}, e
	}
	var d struct {
		SchemaVersion int      `json:"schemaVersion"`
		Repositories  []string `json:"repositories"`
	}
	if e := json.Unmarshal(b, &d); e != nil {
		return SourceGraphConfig{}, e
	}
	if d.SchemaVersion != 1 || len(d.Repositories) < 1 || len(d.Repositories) > 64 {
		return SourceGraphConfig{}, errors.New("source graph is invalid")
	}
	sortStrings(d.Repositories)
	for i, r := range d.Repositories {
		if !ValidRepository(r) || i > 0 && d.Repositories[i-1] == r {
			return SourceGraphConfig{}, errors.New("source graph repository identity is invalid")
		}
	}
	found := false
	for _, r := range d.Repositories {
		if r == root.Repository {
			found = true
		}
	}
	if !found {
		return SourceGraphConfig{}, errors.New("source graph omits webhook repository")
	}
	return SourceGraphConfig{Repositories: d.Repositories}, nil
}
func readBoundedFile(path string, max int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 2 || st.Size() > int64(max) {
		return nil, errors.New("source graph must be a bounded regular file")
	}
	return readBounded(f, max)
}
