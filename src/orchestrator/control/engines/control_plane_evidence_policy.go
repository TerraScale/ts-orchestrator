package engines

type EvidencePolicy struct {
	Lane                  EvidenceLane
	ColdRunRequired       bool
	MinimumTests          EvidenceCount
	MinimumBranchCoverage EvidencePercentage
	MinimumMutationScore  EvidencePercentage
	MinimumPropertyCases  EvidenceCount
	MinimumModelSchedules EvidenceCount
	MinimumFuzzDuration   EvidenceDurationSeconds
	MinimumFuzzCases      EvidenceCount
	MinimumFlakeCleanRuns EvidenceCount
	ReuseAllowed          bool
	IsWellFormed          bool
	requiredDomains       map[EvidenceDomain]struct{}
	requiredArchitectures map[EvidenceArchitecture]struct{}
	permittedExclusions   map[EvidenceExclusionId]struct{}
}

func NewEvidencePolicy(lane EvidenceLane, requiredDomains []EvidenceDomain, coldRunRequired bool,
	minimumTests EvidenceCount, minimumBranchCoverage EvidencePercentage, minimumMutationScore EvidencePercentage,
	minimumPropertyCases EvidenceCount, minimumModelSchedules EvidenceCount,
	minimumFuzzDuration EvidenceDurationSeconds, minimumFuzzCases EvidenceCount,
	minimumFlakeCleanRuns EvidenceCount, permittedExclusions []EvidenceExclusionId,
	requiredArchitectures []EvidenceArchitecture, reuseAllowed bool, maximumEntries int) *EvidencePolicy {
	domains, domainsValid := evidenceCollectionsSnapshot(requiredDomains, maximumEntries, true)
	domainsValid = domainsValid && evidenceAllDefined(domains, evidenceDomainIsDefined) &&
		evidenceNoneUnknownDomain(domains)
	architectures, architecturesValid := evidenceCollectionsSnapshot(requiredArchitectures, maximumEntries, true)
	architecturesValid = architecturesValid && evidenceAllDefined(architectures, evidenceArchitectureIsDefined) &&
		evidenceNoneUnknownArchitecture(architectures)
	exclusions, exclusionsValid := evidenceCollectionsSnapshot(permittedExclusions, maximumEntries, false)

	domainSet := map[EvidenceDomain]struct{}{}
	for _, domain := range domains {
		domainSet[domain] = struct{}{}
	}
	architectureSet := map[EvidenceArchitecture]struct{}{}
	for _, architecture := range architectures {
		architectureSet[architecture] = struct{}{}
	}
	exclusionSet := map[EvidenceExclusionId]struct{}{}
	for _, exclusion := range exclusions {
		exclusionSet[exclusion] = struct{}{}
	}

	policy := &EvidencePolicy{Lane: lane, ColdRunRequired: coldRunRequired, MinimumTests: minimumTests,
		MinimumBranchCoverage: minimumBranchCoverage, MinimumMutationScore: minimumMutationScore,
		MinimumPropertyCases: minimumPropertyCases, MinimumModelSchedules: minimumModelSchedules,
		MinimumFuzzDuration: minimumFuzzDuration, MinimumFuzzCases: minimumFuzzCases,
		MinimumFlakeCleanRuns: minimumFlakeCleanRuns, ReuseAllowed: reuseAllowed,
		requiredDomains: domainSet, requiredArchitectures: architectureSet,
		permittedExclusions: exclusionSet}
	policy.IsWellFormed = evidenceLaneIsDefined(lane) && lane != EvidenceLaneUnknown && maximumEntries > 0 &&
		domainsValid && len(domainSet) == len(domains) &&
		architecturesValid && len(architectureSet) == len(architectures) &&
		exclusionsValid && len(exclusionSet) == len(exclusions) &&
		minimumTests.IsValid() && minimumBranchCoverage.IsValid() && minimumMutationScore.IsValid() &&
		minimumPropertyCases.IsValid() && minimumModelSchedules.IsValid() && minimumFuzzDuration.IsValid() &&
		minimumFuzzCases.IsValid() && minimumFlakeCleanRuns.IsValid()
	return policy
}

func (p *EvidencePolicy) RequiredDomains() map[EvidenceDomain]struct{} { return p.requiredDomains }
func (p *EvidencePolicy) RequiredArchitectures() map[EvidenceArchitecture]struct{} {
	return p.requiredArchitectures
}

// Permits ports the internal exclusion check.
func (p *EvidencePolicy) Permits(id EvidenceExclusionId) bool {
	_, present := p.permittedExclusions[id]
	return present
}

func evidenceAllDefined[T ~int](values []T, isDefined func(T) bool) bool {
	for _, value := range values {
		if !isDefined(value) {
			return false
		}
	}
	return true
}

func evidenceNoneUnknownDomain(values []EvidenceDomain) bool {
	for _, value := range values {
		if value == EvidenceDomainUnknown {
			return false
		}
	}
	return true
}

func evidenceNoneUnknownArchitecture(values []EvidenceArchitecture) bool {
	for _, value := range values {
		if value == EvidenceArchitectureUnknown {
			return false
		}
	}
	return true
}

type EvidencePolicyResult struct {
	Code EvidenceCode
}

func (r EvidencePolicyResult) IsAccepted() bool { return r.Code == EvidenceCodeAllowed }

func evidencePolicyAccept() EvidencePolicyResult                  { return EvidencePolicyResult{EvidenceCodeAllowed} }
func evidencePolicyReject(code EvidenceCode) EvidencePolicyResult { return EvidencePolicyResult{code} }

var EvidencePolicyEvaluator evidencePolicyEvaluator

type evidencePolicyEvaluator struct{}

func (evidencePolicyEvaluator) Evaluate(manifest *EvidenceManifest, policy *EvidencePolicy) EvidencePolicyResult {
	if manifest == nil || !manifest.IsWellFormed || policy == nil || !policy.IsWellFormed ||
		manifest.Lane != policy.Lane {
		return evidencePolicyReject(EvidenceCodeInvalidInput)
	}
	subject := manifest.Subject
	var suiteTotal, fuzzTotal uint64
	for _, suite := range subject.Suites {
		sum, ok := checkedAddU64(suiteTotal, suite.Tests.Value)
		if !ok {
			return evidencePolicyReject(EvidenceCodeArithmeticOverflow)
		}
		suiteTotal = sum
		for _, value := range []uint64{suite.PropertyCases.Value, suite.ModelSchedules.Value, suite.ModelSeeds.Value} {
			sum, ok := checkedAddU64(suiteTotal, value)
			if !ok {
				return evidencePolicyReject(EvidenceCodeArithmeticOverflow)
			}
			suiteTotal = sum
		}
	}
	for _, fuzz := range subject.Fuzz {
		sum, ok := checkedAddU64(fuzzTotal, fuzz.Cases.Value)
		if !ok {
			return evidencePolicyReject(EvidenceCodeArithmeticOverflow)
		}
		fuzzTotal = sum
		sum, ok = checkedAddU64(fuzzTotal, fuzz.Duration.Value)
		if !ok {
			return evidencePolicyReject(EvidenceCodeArithmeticOverflow)
		}
		fuzzTotal = sum
	}
	if policy.ColdRunRequired && subject.Execution != EvidenceExecutionKindCold {
		return evidencePolicyReject(EvidenceCodeFullExecutionRequired)
	}
	if subject.Execution == EvidenceExecutionKindContentAddressedReuse && !policy.ReuseAllowed {
		return evidencePolicyReject(EvidenceCodeReuseDenied)
	}
	if subject.Execution == EvidenceExecutionKindContentAddressedReuse {
		if subject.ReuseProof == nil {
			return evidencePolicyReject(EvidenceCodeInvalidInput)
		}
		reuse := EvidenceReuseEvaluator.Evaluate(&subject.ReuseProof.Expected, &subject.ReuseProof.Candidate,
			policy, subject.ReuseProof.Change)
		if !reuse.IsReusable() {
			return evidencePolicyReject(reuse.Code)
		}
	}
	suiteDomainCount := map[EvidenceDomain]int{}
	for _, suite := range subject.Suites {
		suiteDomainCount[suite.Domain]++
	}
	for _, count := range suiteDomainCount {
		if count > 1 {
			return evidencePolicyReject(EvidenceCodeDuplicateDomain)
		}
	}
	corpusDomainCount := map[EvidenceDomain]int{}
	for _, corpus := range subject.ModelCorpora {
		corpusDomainCount[corpus.Domain]++
	}
	for _, count := range corpusDomainCount {
		if count > 1 {
			return evidencePolicyReject(EvidenceCodeDuplicateDomain)
		}
	}
	suiteDomains := map[EvidenceDomain]struct{}{}
	for _, suite := range subject.Suites {
		suiteDomains[suite.Domain] = struct{}{}
	}
	corpusDomains := map[EvidenceDomain]struct{}{}
	for _, corpus := range subject.ModelCorpora {
		corpusDomains[corpus.Domain] = struct{}{}
	}
	if len(suiteDomains) != len(corpusDomains) {
		return evidencePolicyReject(EvidenceCodeMissingDomain)
	}
	for domain := range suiteDomains {
		if _, present := corpusDomains[domain]; !present {
			return evidencePolicyReject(EvidenceCodeMissingDomain)
		}
	}
	distinctBinaries := map[EvidenceTestBinaryId]struct{}{}
	for _, binary := range subject.TestBinaries {
		distinctBinaries[binary.Identity] = struct{}{}
	}
	if len(distinctBinaries) != len(subject.TestBinaries) {
		return evidencePolicyReject(EvidenceCodeInvalidInput)
	}
	distinctTargets := map[EvidenceFuzzTargetId]struct{}{}
	for _, fuzz := range subject.Fuzz {
		distinctTargets[fuzz.Target] = struct{}{}
	}
	if len(distinctTargets) != len(subject.Fuzz) {
		return evidencePolicyReject(EvidenceCodeInvalidInput)
	}
	architectureCount := map[EvidenceArchitecture]int{}
	distinctArtifacts := map[EvidenceArtifactId]struct{}{}
	for _, artifact := range subject.Artifacts {
		architectureCount[artifact.Architecture]++
		distinctArtifacts[artifact.Identity] = struct{}{}
	}
	for _, count := range architectureCount {
		if count != 1 {
			return evidencePolicyReject(EvidenceCodeInvalidArchitecture)
		}
	}
	if len(distinctArtifacts) != len(subject.Artifacts) {
		return evidencePolicyReject(EvidenceCodeInvalidArchitecture)
	}
	actualArchitectures := map[EvidenceArchitecture]struct{}{}
	for _, artifact := range subject.Artifacts {
		actualArchitectures[artifact.Architecture] = struct{}{}
	}
	if len(actualArchitectures) != len(policy.requiredArchitectures) {
		return evidencePolicyReject(EvidenceCodeInvalidArchitecture)
	}
	for architecture := range actualArchitectures {
		if _, present := policy.requiredArchitectures[architecture]; !present {
			return evidencePolicyReject(EvidenceCodeInvalidArchitecture)
		}
	}
	for _, suite := range subject.Suites {
		if suite.Result != EvidenceResultPassed {
			return evidencePolicyReject(EvidenceCodeResultFailed)
		}
	}
	for _, suite := range subject.Suites {
		if suite.SurvivingSafetyMutants.Value != 0 {
			return evidencePolicyReject(EvidenceCodeSafetyMutantSurvived)
		}
	}
	for domain := range policy.requiredDomains {
		if _, present := suiteDomains[domain]; !present {
			return evidencePolicyReject(EvidenceCodeMissingDomain)
		}
	}
	for _, suite := range subject.Suites {
		if suite.Tests.Value < policy.MinimumTests.Value || suite.PropertyCases.Value < policy.MinimumPropertyCases.Value ||
			suite.BranchCoverage.Value < policy.MinimumBranchCoverage.Value ||
			suite.MutationScore.Value < policy.MinimumMutationScore.Value ||
			suite.ModelSchedules.Value < policy.MinimumModelSchedules.Value ||
			suite.FlakeCleanRuns.Value < policy.MinimumFlakeCleanRuns.Value {
			return evidencePolicyReject(EvidenceCodeThresholdNotMet)
		}
	}
	for _, fuzz := range subject.Fuzz {
		if fuzz.Result != EvidenceResultPassed {
			return evidencePolicyReject(EvidenceCodeResultFailed)
		}
	}
	for _, fuzz := range subject.Fuzz {
		if fuzz.Duration.Value < policy.MinimumFuzzDuration.Value || fuzz.Cases.Value < policy.MinimumFuzzCases.Value {
			return evidencePolicyReject(EvidenceCodeThresholdNotMet)
		}
	}
	forbidden := map[EvidenceExclusionKind]bool{
		EvidenceExclusionKindSafety: true, EvidenceExclusionKindAuthorization: true,
		EvidenceExclusionKindDurability: true, EvidenceExclusionKindDeletion: true,
		EvidenceExclusionKindStateTransition: true, EvidenceExclusionKindValidation: true,
		EvidenceExclusionKindOwnership: true, EvidenceExclusionKindFencing: true,
		EvidenceExclusionKindRetry: true, EvidenceExclusionKindCompensation: true,
		EvidenceExclusionKindAdapterClassification: true,
	}
	for _, exclusion := range subject.Exclusions {
		if forbidden[exclusion.Kind] {
			return evidencePolicyReject(EvidenceCodeForbiddenExclusion)
		}
	}
	for _, exclusion := range subject.Exclusions {
		if (exclusion.Kind != EvidenceExclusionKindGeneratedCode &&
			exclusion.Kind != EvidenceExclusionKindTrivialWiring) || !policy.Permits(exclusion.Identity) {
			return evidencePolicyReject(EvidenceCodeForbiddenExclusion)
		}
	}
	if subject.L0C.Result != EvidenceResultPassed || subject.Checks.Analyzer != EvidenceResultPassed ||
		subject.Checks.Dependency != EvidenceResultPassed || subject.Checks.Vulnerability != EvidenceResultPassed ||
		subject.Checks.License != EvidenceResultPassed || subject.Checks.SecretScan != EvidenceResultPassed {
		return evidencePolicyReject(EvidenceCodeResultFailed)
	}
	return evidencePolicyAccept()
}

func checkedAddU64(left, right uint64) (uint64, bool) {
	sum := left + right
	if sum < left {
		return 0, false
	}
	return sum, true
}

type EvidenceReuseFingerprint struct {
	Source              EvidenceSha256
	TransitiveContracts EvidenceSha256
	Tests               EvidenceSha256
	Corpus              EvidenceSha256
	Dependencies        EvidenceSha256
	Generators          EvidenceSha256
	Schemas             EvidenceSha256
	Toolchain           EvidenceSha256
}

type EvidenceReuseProof struct {
	Expected  EvidenceReuseFingerprint
	Candidate EvidenceReuseFingerprint
	Change    EvidenceChangeKind
}

type EvidenceReuseResult struct {
	Code EvidenceCode
}

func (r EvidenceReuseResult) IsReusable() bool { return r.Code == EvidenceCodeAllowed }

var EvidenceReuseEvaluator evidenceReuseEvaluator

type evidenceReuseEvaluator struct{}

func (evidenceReuseEvaluator) Evaluate(expected, candidate *EvidenceReuseFingerprint, policy *EvidencePolicy,
	change EvidenceChangeKind) EvidenceReuseResult {
	if !evidenceValidFingerprint(expected) || !evidenceValidFingerprint(candidate) ||
		policy == nil || !policy.IsWellFormed || !evidenceChangeKindIsDefined(change) ||
		change == EvidenceChangeKindUnknown {
		return EvidenceReuseResult{Code: EvidenceCodeInvalidInput}
	}
	if !policy.ReuseAllowed {
		return EvidenceReuseResult{Code: EvidenceCodeReuseDenied}
	}
	if change == EvidenceChangeKindSharedContract || change == EvidenceChangeKindSecurity ||
		change == EvidenceChangeKindToolchain || change == EvidenceChangeKindColdFirstCandidate {
		return EvidenceReuseResult{Code: EvidenceCodeFullExecutionRequired}
	}
	if *expected == *candidate {
		return EvidenceReuseResult{Code: EvidenceCodeAllowed}
	}
	return EvidenceReuseResult{Code: EvidenceCodeReuseDenied}
}

func evidenceValidFingerprint(fingerprint *EvidenceReuseFingerprint) bool {
	return fingerprint != nil
}
