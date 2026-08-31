package control

import "sort"

type EvidenceTestBinary struct {
	Identity EvidenceTestBinaryId
	Digest   EvidenceSha256
}

type EvidenceArchitectureArtifact struct {
	Identity     EvidenceArtifactId
	Architecture EvidenceArchitecture
	Digest       EvidenceSha256
}

type EvidenceSuiteResult struct {
	Suite                  EvidenceSuiteId
	Domain                 EvidenceDomain
	Tests                  EvidenceCount
	PropertyCases          EvidenceCount
	BranchCoverage         EvidencePercentage
	MutationScore          EvidencePercentage
	SurvivingSafetyMutants EvidenceNonNegativeCount
	ModelSchedules         EvidenceCount
	ModelSeeds             EvidenceCount
	FlakeCleanRuns         EvidenceCount
	Result                 EvidenceResult
}

type EvidenceFuzzResult struct {
	Target       EvidenceFuzzTargetId
	Corpus       EvidenceCorpusId
	CorpusDigest EvidenceSha256
	Duration     EvidenceDurationSeconds
	Cases        EvidenceCount
	Result       EvidenceResult
}

type EvidenceModelCorpus struct {
	Domain EvidenceDomain
	Corpus EvidenceCorpusId
	Digest EvidenceSha256
}

type EvidenceExclusion struct {
	Identity EvidenceExclusionId
	Kind     EvidenceExclusionKind
}

type EvidenceCheckResults struct {
	Analyzer      EvidenceResult
	Dependency    EvidenceResult
	Vulnerability EvidenceResult
	License       EvidenceResult
	SecretScan    EvidenceResult
}

type EvidenceRequirementTrace struct {
	Identity     EvidenceTraceId
	Digest       EvidenceSha256
	Requirements EvidenceCount
	Invariants   EvidenceCount
	Errors       EvidenceCount
	Transitions  EvidenceCount
}

type EvidenceL0CResult struct {
	Identity EvidenceL0CId
	Digest   EvidenceSha256
	Result   EvidenceResult
}

type EvidenceSubject struct {
	Tree             EvidenceTreeId
	TreeDigest       EvidenceSha256
	DependencyLock   EvidenceDependencyLockId
	DependencyDigest EvidenceSha256
	Schema           EvidenceSchemaId
	SchemaDigest     EvidenceSha256
	TestBinaries     []EvidenceTestBinary
	Artifacts        []EvidenceArchitectureArtifact
	Suites           []EvidenceSuiteResult
	Fuzz             []EvidenceFuzzResult
	ModelCorpora     []EvidenceModelCorpus
	Exclusions       []EvidenceExclusion
	Trace            EvidenceRequirementTrace
	L0C              EvidenceL0CResult
	Checks           EvidenceCheckResults
	ToolchainDigest  EvidenceSha256
	Approver         EvidenceApproverId
	Execution        EvidenceExecutionKind
	ReuseProof       *EvidenceReuseProof
	IsWellFormed     bool
}

func evidenceCopyBounded[T any](source []T, maximum int) ([]T, bool) {
	values, valid := evidenceCollectionsSnapshot(source, maximum, true)
	if !valid {
		return values, false
	}
	return values, true
}

func NewEvidenceSubject(tree EvidenceTreeId, treeDigest EvidenceSha256, dependencyLock EvidenceDependencyLockId,
	dependencyDigest EvidenceSha256, schema EvidenceSchemaId, schemaDigest EvidenceSha256,
	testBinaries []EvidenceTestBinary, artifacts []EvidenceArchitectureArtifact, suites []EvidenceSuiteResult,
	trace EvidenceRequirementTrace, fuzz []EvidenceFuzzResult, modelCorpora []EvidenceModelCorpus,
	l0C EvidenceL0CResult, checks EvidenceCheckResults, toolchainDigest EvidenceSha256,
	approver EvidenceApproverId, execution EvidenceExecutionKind, reuseProof *EvidenceReuseProof,
	exclusions []EvidenceExclusion, maximumEntries int) *EvidenceSubject {
	binaries, binariesValid := evidenceCopyBounded(testBinaries, maximumEntries)
	artifactList, artifactsValid := evidenceCopyBounded(artifacts, maximumEntries)
	suiteList, suitesValid := evidenceCopyBounded(suites, maximumEntries)
	fuzzList, fuzzValid := evidenceCopyBounded(fuzz, maximumEntries)
	corporaList, corporaValid := evidenceCopyBounded(modelCorpora, maximumEntries)
	exclusionList, exclusionsValid := evidenceCollectionsSnapshot(exclusions, maximumEntries, false)

	sort.Slice(binaries, func(i, j int) bool { return binaries[i].Identity.Value < binaries[j].Identity.Value })
	sort.Slice(artifactList, func(i, j int) bool {
		if artifactList[i].Architecture != artifactList[j].Architecture {
			return artifactList[i].Architecture < artifactList[j].Architecture
		}
		return artifactList[i].Identity.Value < artifactList[j].Identity.Value
	})
	sort.Slice(suiteList, func(i, j int) bool {
		if suiteList[i].Domain != suiteList[j].Domain {
			return suiteList[i].Domain < suiteList[j].Domain
		}
		return suiteList[i].Suite.Value < suiteList[j].Suite.Value
	})
	sort.Slice(fuzzList, func(i, j int) bool { return fuzzList[i].Target.Value < fuzzList[j].Target.Value })
	sort.Slice(corporaList, func(i, j int) bool {
		if corporaList[i].Domain != corporaList[j].Domain {
			return corporaList[i].Domain < corporaList[j].Domain
		}
		return corporaList[i].Corpus.Value < corporaList[j].Corpus.Value
	})
	sort.Slice(exclusionList, func(i, j int) bool {
		return exclusionList[i].Identity.Value < exclusionList[j].Identity.Value
	})

	subject := &EvidenceSubject{Tree: tree, TreeDigest: treeDigest, DependencyLock: dependencyLock,
		DependencyDigest: dependencyDigest, Schema: schema, SchemaDigest: schemaDigest,
		TestBinaries: binaries, Artifacts: artifactList, Suites: suiteList, Fuzz: fuzzList,
		ModelCorpora: corporaList, Exclusions: exclusionList, Trace: trace, L0C: l0C, Checks: checks,
		ToolchainDigest: toolchainDigest, Approver: approver, Execution: execution, ReuseProof: reuseProof}
	subject.IsWellFormed = tree.IsValid() && dependencyLock.IsValid() && schema.IsValid() &&
		binariesValid && artifactsValid && suitesValid && fuzzValid && corporaValid && exclusionsValid &&
		trace.Identity.IsValid() && l0C.Identity.IsValid() &&
		evidenceExecutionKindIsDefined(execution) && execution != EvidenceExecutionKindUnknown &&
		((execution == EvidenceExecutionKindCold && reuseProof == nil) ||
			(execution != EvidenceExecutionKindCold && reuseProof != nil)) &&
		evidenceValidEntries(subject)
	return subject
}

func evidenceValidEntries(subject *EvidenceSubject) bool {
	for _, binary := range subject.TestBinaries {
		if !binary.Identity.IsValid() {
			return false
		}
	}
	for _, artifact := range subject.Artifacts {
		if !artifact.Identity.IsValid() || !evidenceArchitectureIsDefined(artifact.Architecture) ||
			artifact.Architecture == EvidenceArchitectureUnknown {
			return false
		}
	}
	for _, suite := range subject.Suites {
		if !suite.Suite.IsValid() || !evidenceDomainIsDefined(suite.Domain) || suite.Domain == EvidenceDomainUnknown ||
			!suite.Tests.IsValid() || !suite.PropertyCases.IsValid() || !suite.BranchCoverage.IsValid() ||
			!suite.MutationScore.IsValid() || !suite.SurvivingSafetyMutants.IsValid() ||
			!suite.ModelSchedules.IsValid() || !suite.ModelSeeds.IsValid() || !suite.FlakeCleanRuns.IsValid() ||
			!evidenceResultIsDefined(suite.Result) || suite.Result == EvidenceResultUnknown {
			return false
		}
	}
	if !subject.Trace.Identity.IsValid() || !subject.Trace.Requirements.IsValid() ||
		!subject.Trace.Invariants.IsValid() || !subject.Trace.Errors.IsValid() ||
		!subject.Trace.Transitions.IsValid() {
		return false
	}
	for _, fuzz := range subject.Fuzz {
		if !fuzz.Target.IsValid() || !fuzz.Corpus.IsValid() || !fuzz.Duration.IsValid() || !fuzz.Cases.IsValid() ||
			!evidenceResultIsDefined(fuzz.Result) || fuzz.Result == EvidenceResultUnknown {
			return false
		}
	}
	for _, corpus := range subject.ModelCorpora {
		if !evidenceDomainIsDefined(corpus.Domain) || corpus.Domain == EvidenceDomainUnknown ||
			!corpus.Corpus.IsValid() {
			return false
		}
	}
	if !subject.L0C.Identity.IsValid() || !evidenceResultIsDefined(subject.L0C.Result) ||
		subject.L0C.Result == EvidenceResultUnknown {
		return false
	}
	for _, check := range []EvidenceResult{subject.Checks.Analyzer, subject.Checks.Dependency,
		subject.Checks.Vulnerability, subject.Checks.License, subject.Checks.SecretScan} {
		if !evidenceResultIsDefined(check) || check == EvidenceResultUnknown {
			return false
		}
	}
	distinctSuites := map[EvidenceSuiteId]struct{}{}
	for _, suite := range subject.Suites {
		distinctSuites[suite.Suite] = struct{}{}
	}
	if len(distinctSuites) != len(subject.Suites) {
		return false
	}
	distinctCorpora := map[EvidenceCorpusId]struct{}{}
	for _, corpus := range subject.ModelCorpora {
		distinctCorpora[corpus.Corpus] = struct{}{}
	}
	if len(distinctCorpora) != len(subject.ModelCorpora) {
		return false
	}
	distinctExclusions := map[EvidenceExclusionId]struct{}{}
	for _, exclusion := range subject.Exclusions {
		if !exclusion.Identity.IsValid() || !evidenceExclusionKindIsDefined(exclusion.Kind) ||
			exclusion.Kind == EvidenceExclusionKindUnknown {
			return false
		}
		distinctExclusions[exclusion.Identity] = struct{}{}
	}
	return len(distinctExclusions) == len(subject.Exclusions)
}

func evidenceSliceEqual[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// ExactEquals ports the internal structural equality helper.
func (s *EvidenceSubject) ExactEquals(other *EvidenceSubject) bool {
	if other == nil {
		return false
	}
	if s.Tree != other.Tree || !s.TreeDigest.Equal(other.TreeDigest) ||
		s.DependencyLock != other.DependencyLock || !s.DependencyDigest.Equal(other.DependencyDigest) ||
		s.Schema != other.Schema || !s.SchemaDigest.Equal(other.SchemaDigest) ||
		s.Trace != other.Trace || s.L0C != other.L0C || s.Checks != other.Checks ||
		!s.ToolchainDigest.Equal(other.ToolchainDigest) || s.Approver != other.Approver ||
		s.Execution != other.Execution {
		return false
	}
	if (s.ReuseProof == nil) != (other.ReuseProof == nil) {
		return false
	}
	if s.ReuseProof != nil && *s.ReuseProof != *other.ReuseProof {
		return false
	}
	return evidenceSliceEqual(s.TestBinaries, other.TestBinaries) && evidenceSliceEqual(s.Artifacts, other.Artifacts) &&
		evidenceSliceEqual(s.Suites, other.Suites) && evidenceSliceEqual(s.Fuzz, other.Fuzz) &&
		evidenceSliceEqual(s.ModelCorpora, other.ModelCorpora) && evidenceSliceEqual(s.Exclusions, other.Exclusions)
}

type EvidenceManifest struct {
	Identity               EvidenceManifestId
	Lane                   EvidenceLane
	Subject                *EvidenceSubject
	CanonicalPayloadDigest EvidenceSha256
	IsWellFormed           bool
}

func NewEvidenceManifest(identity EvidenceManifestId, lane EvidenceLane, subject *EvidenceSubject,
	canonicalPayloadDigest EvidenceSha256) *EvidenceManifest {
	wellFormed := identity.IsValid() && evidenceLaneIsDefined(lane) && lane != EvidenceLaneUnknown &&
		subject != nil && subject.IsWellFormed
	return &EvidenceManifest{Identity: identity, Lane: lane, Subject: subject,
		CanonicalPayloadDigest: canonicalPayloadDigest, IsWellFormed: wellFormed}
}
