package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// NatsSubjectTaxonomy is the closed NATS subject taxonomy for the v1 control
// messaging protocol. This is the
// single canonical definition of every subject namespace root and every
// concrete subject shape the production adapters may use; adapters compose
// subjects exclusively through these definitions. The closed family set is
// generated from the checked-in protocol manifest (protocol-manifest.json) and
// validated against it: the taxonomy and the manifest cannot drift apart
// silently. The taxonomy is infrastructure-free: it knows subject grammar, not
// NATS clients.
//
// Every subject constant is a method (NatsSubjectTaxonomy.Root(),
// NatsSubjectTaxonomy.GlobalRoot(), ...). Methods that can fail return an
// error as their second value.
var NatsSubjectTaxonomy natsSubjectTaxonomy

type natsSubjectTaxonomy struct{}

// Root returns the one versioned control-plane
// subject root. The product plane is NOT rooted here.
func (natsSubjectTaxonomy) Root() string { return "ts.orch.v1" }

// GlobalScopeToken is the reserved
// scope token that names the global authority namespace.
func (natsSubjectTaxonomy) GlobalScopeToken() string { return "global" }

// RegionPlaceholderToken mirrors the manifest <region> placeholder.
func (natsSubjectTaxonomy) RegionPlaceholderToken() string { return "<region>" }

// AgentHashPlaceholderToken mirrors the manifest <agent-hash> placeholder.
func (natsSubjectTaxonomy) AgentHashPlaceholderToken() string { return "<agent-hash>" }

// GlobalRoot is the global-authority
// namespace root (GRU-owned global journals, releases, and directory).
func (natsSubjectTaxonomy) GlobalRoot() string {
	return NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.GlobalScopeToken()
}

// GlobalDirectoryQuerySubject mirrors the directory query service subject
// served by the GRU directory-service identity.
func (natsSubjectTaxonomy) GlobalDirectoryQuerySubject() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".query.cells"
}

// GlobalCellSpecPrefix mirrors the prefix for durable globally signed native
// CellSpecs, one subject per Region.
func (natsSubjectTaxonomy) GlobalCellSpecPrefix() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".desired.gitops"
}

// GlobalAcceptedReleasePrefix mirrors the prefix of the accepted global
// release journal under the closed release family.
func (natsSubjectTaxonomy) GlobalAcceptedReleasePrefix() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".release.accepted"
}

// GlobalDeliverySubject admits original signed delivery intents to the live GRU master.
func (natsSubjectTaxonomy) GlobalDeliverySubject() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".release.delivery"
}

// CiForgejoTriggerSubject mirrors the normalized Forgejo trigger decisions
// subject consumed by the leader-only global CI consumer.
func (natsSubjectTaxonomy) CiForgejoTriggerSubject() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".release.ci.forgejo"
}

// CiRuntimeProofSubject mirrors the native CI runtime observations subject
// verified by the global authority.
func (natsSubjectTaxonomy) CiRuntimeProofSubject() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".release.ci.runtime-proof"
}

// CiJobSubjectPrefix mirrors the prefix for fenced per-runner CI command
// inboxes (zone + identity hash).
func (natsSubjectTaxonomy) CiJobSubjectPrefix() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".release.ci.job"
}

// DesiredFamilySegment mirrors the desired-state family segment, shared by the
// global and regional scopes.
func (natsSubjectTaxonomy) DesiredFamilySegment() string { return "desired" }

// ReleaseFamilySegment mirrors the global release and delivery family segment.
func (natsSubjectTaxonomy) ReleaseFamilySegment() string { return "release" }

// QueryFamilySegment mirrors the query family segment, shared by the global
// and regional scopes.
func (natsSubjectTaxonomy) QueryFamilySegment() string { return "query" }

// CommandFamilySegment mirrors the regional command family segment.
func (natsSubjectTaxonomy) CommandFamilySegment() string { return "command" }

// ObservationFamilySegment mirrors the regional observation family segment.
func (natsSubjectTaxonomy) ObservationFamilySegment() string { return "observation" }

// OperationFamilySegment mirrors the regional operation family segment.
func (natsSubjectTaxonomy) OperationFamilySegment() string { return "operation" }

// RegionalAuditPrefixSegment mirrors the regional audit family segment.
func (natsSubjectTaxonomy) RegionalAuditPrefixSegment() string { return "audit" }

// RegionalAgentPrefixSegment mirrors the regional host-agent family segment;
// deeper tokens pin the admitted agent hash.
func (natsSubjectTaxonomy) RegionalAgentPrefixSegment() string { return "agent" }

// RegionalDesiredFamilyTemplate mirrors the cell-substitution template for
// the durable regional desired-state family.
func (natsSubjectTaxonomy) RegionalDesiredFamilyTemplate() string {
	return NatsSubjectTaxonomy.Root() + ".{cell}." + NatsSubjectTaxonomy.DesiredFamilySegment() + ".>"
}

// RegionalOperationFamilyTemplate mirrors the cell-substitution template for
// the durable regional operation family.
func (natsSubjectTaxonomy) RegionalOperationFamilyTemplate() string {
	return NatsSubjectTaxonomy.Root() + ".{cell}." + NatsSubjectTaxonomy.OperationFamilySegment() + ".>"
}

// RegionalObservationFamilyTemplate mirrors the cell-substitution template for
// the durable regional observation family.
func (natsSubjectTaxonomy) RegionalObservationFamilyTemplate() string {
	return NatsSubjectTaxonomy.Root() + ".{cell}." + NatsSubjectTaxonomy.ObservationFamilySegment() + ".>"
}

// RegionalCellSpecTemplate mirrors the cell-substitution template for one
// durable signed regional CellSpec.
func (natsSubjectTaxonomy) RegionalCellSpecTemplate() string {
	return NatsSubjectTaxonomy.Root() + ".{cell}.desired.gitops"
}

// RegionalRuntimeStartupTemplate mirrors the cell-substitution template for
// all regional runtime-startup observations.
func (natsSubjectTaxonomy) RegionalRuntimeStartupTemplate() string {
	return NatsSubjectTaxonomy.Root() + ".{cell}.observation.runtime.started.>"
}

// GlobalCiFamilyPattern mirrors the complete global CI family under the closed
// release namespace.
func (natsSubjectTaxonomy) GlobalCiFamilyPattern() string {
	return NatsSubjectTaxonomy.GlobalRoot() + ".release.ci.>"
}

// AgentHashTokenLength is the length of the truncated
// SHA-256 host-agent hash token used in subjects.
func (natsSubjectTaxonomy) AgentHashTokenLength() int { return 24 }

// GrammarLimits returns the taxonomy's bounded subject-grammar policy.
func (natsSubjectTaxonomy) GrammarLimits() *SubjectGrammarLimits {
	return taxonomyGrammarLimits
}

// Families returns the closed subject families,
// generated from the checked-in protocol manifest and validated against the
// compiled taxonomy. Any disagreement panics: the manifest is the single
// source of truth.
func (natsSubjectTaxonomy) Families() []ProtocolSubjectFamily {
	manifestFamiliesOnce.Do(func() {
		violations := NatsSubjectTaxonomy.ManifestValidationViolations()
		if len(violations) > 0 {
			panic("The checked-in protocol manifest disagrees with the NATS subject taxonomy: " +
				strings.Join(violations, "; "))
		}
	})

	return ProtocolManifestLoaded().SubjectFamilies
}

var (
	taxonomyGrammarLimits = createGrammarLimits()
	manifestFamiliesOnce  sync.Once
)

// RegionalRoot returns the regional control
// namespace root for one Region (ts.orch.v1.<region>).
func (natsSubjectTaxonomy) RegionalRoot(cell string) (string, error) {
	if cellTokenRuleIsValid(cell) && cell != NatsSubjectTaxonomy.GlobalScopeToken() {
		return NatsSubjectTaxonomy.Root() + "." + cell, nil
	}

	return "", errors.New(
		"The region subject token is not a lowercase DNS-style token and must not name the reserved global scope. (Parameter 'cell')")
}

// RegionalRootForRegionCode returns the regional
// control namespace root for one canonical uppercase RegionCode.
func (natsSubjectTaxonomy) RegionalRootForRegionCode(regionCode string) (string, error) {
	token, err := NatsSubjectTaxonomy.SubjectTokenForRegion(regionCode)
	if err != nil {
		return "", err
	}

	return NatsSubjectTaxonomy.RegionalRoot(token)
}

// CellSpecSubject returns the durable signed regional
// CellSpec subject (ts.orch.v1.<region>.desired.gitops).
func (natsSubjectTaxonomy) CellSpecSubject(cell string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	return root + ".desired.gitops", nil
}

// RegionalFamilyPattern returns the terminal permission
// pattern of one closed regional family.
func (natsSubjectTaxonomy) RegionalFamilyPattern(cell, familySegment string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	return root + "." + familySegment + ".>", nil
}

// GlobalFamilyPattern returns the terminal permission
// pattern of one closed global family.
func (natsSubjectTaxonomy) GlobalFamilyPattern(familySegment string) string {
	return NatsSubjectTaxonomy.GlobalRoot() + "." + familySegment + ".>"
}

// ControllerHealthSubject returns the controller health query subject of one cell.
func (natsSubjectTaxonomy) ControllerHealthSubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".query.health")
}

// ControllerInstanceHealthSubject returns the per-instance controller health
// subject of one cell.
func (natsSubjectTaxonomy) ControllerInstanceHealthSubject(cell, instance string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	token, err := requireSubjectToken(instance, "instance")
	if err != nil {
		return "", err
	}

	return root + ".query.health." + token, nil
}

// ControllerStatusSubject returns the controller status query subject of one cell.
func (natsSubjectTaxonomy) ControllerStatusSubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".query.status")
}

// ControllerMembersSubject returns the controller members query subject of one cell.
func (natsSubjectTaxonomy) ControllerMembersSubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".query.members")
}

// ControllerStatsSubject returns the read-only service
// statistics endpoint subject (no mutation surface).
func (natsSubjectTaxonomy) ControllerStatsSubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".query.stats")
}

// DirectDeliverySubject returns the signed
// direct-delivery mutation admission subject (request/reply, lossy transport).
func (natsSubjectTaxonomy) DirectDeliverySubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".command.delivery")
}

// ControllerInboxPrefix returns the ephemeral
// controller inbox prefix under the command family; the NATS client appends
// its unique suffix.
func (natsSubjectTaxonomy) ControllerInboxPrefix(cell, publicKey string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	token, err := requireSubjectToken(publicKey, "publicKey")
	if err != nil {
		return "", err
	}

	return root + ".command.reply." + token, nil
}

// OperationJournalCreateSubject returns the
// ephemeral regional operation-journal append RPC.
func (natsSubjectTaxonomy) OperationJournalCreateSubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".command.journal.create")
}

// OperationJournalUpdateSubject returns the regional operation-journal update
// RPC subject of one cell.
func (natsSubjectTaxonomy) OperationJournalUpdateSubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".command.journal.update")
}

// OperationJournalReplySubject returns the per-caller operation-journal reply
// subject of one cell.
func (natsSubjectTaxonomy) OperationJournalReplySubject(cell, callerIdentity, nonce string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	identity, err := requireSubjectToken(callerIdentity, "callerIdentity")
	if err != nil {
		return "", err
	}

	nonceToken, err := requireNonce(nonce, "nonce")
	if err != nil {
		return "", err
	}

	return root + ".command.journal.reply." + identity + "." + nonceToken, nil
}

// RuntimeStartupSubject returns the runtime startup
// observation of the closed observation family.
func (natsSubjectTaxonomy) RuntimeStartupSubject(cell, instance string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	token, err := requireSubjectToken(instance, "instance")
	if err != nil {
		return "", err
	}

	return root + ".observation.runtime.started." + token, nil
}

// RuntimeStartupPattern returns the subject pattern of all runtime-startup
// observations for one Region.
func (natsSubjectTaxonomy) RuntimeStartupPattern(cell string) (string, error) {
	return withRegionalRoot(cell, ".observation.runtime.started.>")
}

// EstateDriftSubject returns the estate drift observation of the closed
// observation family: the reconciler's structured drift events for one
// Region's CELL_EVENTS history (replayable semantic class).
func (natsSubjectTaxonomy) EstateDriftSubject(cell string) (string, error) {
	return withRegionalRoot(cell, ".observation.estate.drift")
}

// RuntimeLifecycleJournalSubject returns the
// private runtime-lifecycle journal RPC under the non-streamed command family.
func (natsSubjectTaxonomy) RuntimeLifecycleJournalSubject(cell, operation string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	token, err := requireSubjectToken(operation, "operation")
	if err != nil {
		return "", err
	}

	return root + ".command.runtime-lifecycle." + token, nil
}

// RuntimeLifecycleJournalReplySubject returns the per-caller runtime-lifecycle
// journal reply subject of one cell.
func (natsSubjectTaxonomy) RuntimeLifecycleJournalReplySubject(cell, callerIdentity, nonce string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	identity, err := requireSubjectToken(callerIdentity, "callerIdentity")
	if err != nil {
		return "", err
	}

	nonceToken, err := requireNonce(nonce, "nonce")
	if err != nil {
		return "", err
	}

	return root + ".command.runtime-lifecycle.reply." + identity + "." + nonceToken, nil
}

// HostAgentSubjectToken returns the fixed SHA-256
// subject token of one admitted host-agent identity (lowercase hex).
func (natsSubjectTaxonomy) HostAgentSubjectToken(agentIdentity string) (string, error) {
	hash, err := NatsSubjectTaxonomy.HostAgentIdentityHash(agentIdentity)
	if err != nil {
		return "", err
	}

	return hash[:NatsSubjectTaxonomy.AgentHashTokenLength()], nil
}

// HostAgentSubjectRoot returns the host-agent subject
// root of one admitted agent: the fixed hash, never the raw identity.
func (natsSubjectTaxonomy) HostAgentSubjectRoot(cell, agentIdentity string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	token, err := NatsSubjectTaxonomy.HostAgentSubjectToken(agentIdentity)
	if err != nil {
		return "", err
	}

	return root + "." + NatsSubjectTaxonomy.RegionalAgentPrefixSegment() + "." + token, nil
}

// HostAgentCommandSubject returns the fenced command
// leaf addressed to exactly one admitted host agent.
func (natsSubjectTaxonomy) HostAgentCommandSubject(cell, agentIdentity, command string) (string, error) {
	root, err := NatsSubjectTaxonomy.HostAgentSubjectRoot(cell, agentIdentity)
	if err != nil {
		return "", err
	}

	token, err := requireSubjectToken(command, "command")
	if err != nil {
		return "", err
	}

	return root + ".command." + token, nil
}

// HostAgentObservationSubject returns the
// observation leaf published by exactly one admitted host agent.
func (natsSubjectTaxonomy) HostAgentObservationSubject(cell, agentIdentity, observation string) (string, error) {
	root, err := NatsSubjectTaxonomy.HostAgentSubjectRoot(cell, agentIdentity)
	if err != nil {
		return "", err
	}

	token, err := requireSubjectToken(observation, "observation")
	if err != nil {
		return "", err
	}

	return root + "." + NatsSubjectTaxonomy.ObservationFamilySegment() + "." + token, nil
}

// HostAgentAcknowledgementSubject returns
// the acknowledgement leaf published by exactly one admitted host agent.
func (natsSubjectTaxonomy) HostAgentAcknowledgementSubject(cell, agentIdentity, acknowledgement string) (string, error) {
	root, err := NatsSubjectTaxonomy.HostAgentSubjectRoot(cell, agentIdentity)
	if err != nil {
		return "", err
	}

	token, err := requireSubjectToken(acknowledgement, "acknowledgement")
	if err != nil {
		return "", err
	}

	return root + ".ack." + token, nil
}

// HostAgentIdentityHash returns the fixed SHA-256 hash
// of an admitted host-agent identity. The raw identity — which may carry
// operator-controlled text — never becomes a subject token.
func (natsSubjectTaxonomy) HostAgentIdentityHash(agentIdentity string) (string, error) {
	if len(agentIdentity) < 1 || len(agentIdentity) > 512 ||
		strings.IndexFunc(agentIdentity, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) >= 0 {
		return "", errors.New("The admitted host-agent identity is not bounded text. (Parameter 'agentIdentity')")
	}

	digest := sha256.Sum256([]byte(agentIdentity))
	return hex.EncodeToString(digest[:]), nil
}

// TryMapRegionCodeToSubjectToken maps
// one registered canonical uppercase RegionCode to its strict lowercase
// subject token. The mapping is bijective: payloads keep the uppercase code
// while subjects use the token.
func (natsSubjectTaxonomy) TryMapRegionCodeToSubjectToken(regionCode string) (string, bool) {
	switch regionCode {
	case "GRU":
		return "gru", true
	case "SFO":
		return "sfo", true
	case "FRA":
		return "fra", true
	default:
		return "", false
	}
}

// TryMapSubjectTokenToRegionCode maps
// one registered strict lowercase subject token back to its canonical
// uppercase RegionCode.
func (natsSubjectTaxonomy) TryMapSubjectTokenToRegionCode(subjectToken string) (string, bool) {
	switch subjectToken {
	case "gru":
		return "GRU", true
	case "sfo":
		return "SFO", true
	case "fra":
		return "FRA", true
	default:
		return "", false
	}
}

// SubjectTokenForRegion returns the strict lowercase
// subject token of one canonical uppercase RegionCode.
func (natsSubjectTaxonomy) SubjectTokenForRegion(regionCode string) (string, error) {
	if token, ok := NatsSubjectTaxonomy.TryMapRegionCodeToSubjectToken(regionCode); ok {
		return token, nil
	}

	return "", errors.New(
		"The RegionCode is not a registered canonical uppercase Region. (Parameter 'regionCode')")
}

// RegionCodeFromSubjectToken returns the canonical
// uppercase RegionCode of one strict lowercase subject token.
func (natsSubjectTaxonomy) RegionCodeFromSubjectToken(subjectToken string) (string, error) {
	if code, ok := NatsSubjectTaxonomy.TryMapSubjectTokenToRegionCode(subjectToken); ok {
		return code, nil
	}

	return "", errors.New(
		"The subject token does not map to a registered canonical Region. (Parameter 'subjectToken')")
}

// GlobalCellSpecSubject returns the durable globally
// signed CellSpec subject for one Region.
func (natsSubjectTaxonomy) GlobalCellSpecSubject(cell string) (string, error) {
	if cellTokenRuleIsValid(cell) && cell != NatsSubjectTaxonomy.GlobalScopeToken() {
		return NatsSubjectTaxonomy.GlobalCellSpecPrefix() + "." + cell, nil
	}

	return "", errors.New(
		"The region subject token is not a lowercase DNS-style token and must not name the reserved global scope. (Parameter 'cell')")
}

// Classify classifies one concrete
// subject into the closed namespace taxonomy. Anything outside the closed set
// — including every SupersededRoot-prefixed subject — classifies as Unknown:
// classification fails closed; callers must reject unknown subjects.
func (natsSubjectTaxonomy) Classify(subject string) NatsSubjectNamespace {
	if subject == "" {
		return NatsSubjectNamespaceUnknown
	}

	tokens := strings.Split(subject, ".")
	if len(tokens) > 0 && isPlatformReservedRoot(tokens[0]) {
		return NatsSubjectNamespacePlatformReserved
	}

	if len(tokens) < 4 {
		return NatsSubjectNamespaceUnknown
	}

	if tokens[0] != "ts" {
		return NatsSubjectNamespaceUnknown
	}

	if tokens[1] != "orch" || tokens[2] != "v1" {
		if tokens[1] == "product" {
			return NatsSubjectNamespaceProductPlane
		}

		return NatsSubjectNamespaceUnknown
	}

	if tokens[3] == NatsSubjectTaxonomy.GlobalScopeToken() {
		if len(tokens) < 5 {
			return NatsSubjectNamespaceUnknown
		}

		if len(tokens) == 6 && tokens[4] == NatsSubjectTaxonomy.QueryFamilySegment() && tokens[5] == "cells" {
			return NatsSubjectNamespaceGlobalDirectory
		}

		if tokens[4] == NatsSubjectTaxonomy.ReleaseFamilySegment() && len(tokens) > 5 && tokens[5] == "ci" {
			return NatsSubjectNamespaceContinuousIntegration
		}

		switch tokens[4] {
		case NatsSubjectTaxonomy.DesiredFamilySegment(),
			NatsSubjectTaxonomy.ReleaseFamilySegment(),
			NatsSubjectTaxonomy.QueryFamilySegment():
			return NatsSubjectNamespaceGlobalAuthority
		default:
			return NatsSubjectNamespaceUnknown
		}
	}

	if !cellTokenRuleIsValid(tokens[3]) {
		return NatsSubjectNamespaceUnknown
	}

	if len(tokens) < 6 {
		return NatsSubjectNamespaceUnknown
	}

	if tokens[4] == NatsSubjectTaxonomy.RegionalAgentPrefixSegment() {
		return NatsSubjectNamespaceAgent
	}

	if tokens[4] == NatsSubjectTaxonomy.RegionalAuditPrefixSegment() {
		return NatsSubjectNamespaceAudit
	}

	if tokens[4] == NatsSubjectTaxonomy.OperationFamilySegment() {
		return NatsSubjectNamespaceOperations
	}

	switch tokens[4] {
	case NatsSubjectTaxonomy.DesiredFamilySegment(),
		NatsSubjectTaxonomy.CommandFamilySegment(),
		NatsSubjectTaxonomy.QueryFamilySegment(),
		NatsSubjectTaxonomy.ObservationFamilySegment():
		return NatsSubjectNamespaceRegionalControl
	default:
		return NatsSubjectNamespaceUnknown
	}
}

// IsControlNamespace reports membership in exactly the seven control
// namespaces of the closed taxonomy; the product-plane business namespace is
// excluded.
func (natsSubjectTaxonomy) IsControlNamespace(ns NatsSubjectNamespace) bool {
	switch ns {
	case NatsSubjectNamespaceGlobalAuthority,
		NatsSubjectNamespaceGlobalDirectory,
		NatsSubjectNamespaceRegionalControl,
		NatsSubjectNamespaceAgent,
		NatsSubjectNamespaceContinuousIntegration,
		NatsSubjectNamespaceOperations,
		NatsSubjectNamespaceAudit:
		return true
	default:
		return false
	}
}

// TryValidatePermissionPattern
// validates one permission pattern against the closed v1 family set. A
// wildcard may never sit at — or span — the scope or family position, so no
// permission can cross a Region boundary; superseded-root patterns are
// rejected outright.
func (natsSubjectTaxonomy) TryValidatePermissionPattern(pattern string) (bool, NatsSubjectPermissionError) {
	compiled, err := SubjectPermissionPatternTryParse(pattern, taxonomyGrammarLimits)
	if compiled == nil || err != SubjectGrammarErrorNone {
		return false, NatsSubjectPermissionErrorMalformedPattern
	}

	tokens := strings.Split(pattern, ".")
	if len(tokens) < 3 || tokens[0] != "ts" || tokens[1] != "orch" || tokens[2] != "v1" {
		if isPlatformReservedRoot(tokens[0]) {
			return false, NatsSubjectPermissionErrorPlatformReserved
		}

		return false, NatsSubjectPermissionErrorOutsideControlRoot
	}

	if len(tokens) < 5 {
		return false, NatsSubjectPermissionErrorWildcardInScopeToken
	}

	scope := tokens[3]
	if scope == "*" || scope == ">" {
		return false, NatsSubjectPermissionErrorWildcardInScopeToken
	}

	isGlobal := scope == NatsSubjectTaxonomy.GlobalScopeToken()
	if !isGlobal && !cellTokenRuleIsValid(scope) {
		return false, NatsSubjectPermissionErrorInvalidRegionToken
	}

	family := tokens[4]
	if family == "*" || family == ">" {
		return false, NatsSubjectPermissionErrorWildcardInFamilyToken
	}

	if !isClosedFamilySegment(isGlobal, family) {
		return false, NatsSubjectPermissionErrorUnknownFamily
	}

	if !isGlobal && family == NatsSubjectTaxonomy.RegionalAgentPrefixSegment() && len(tokens) > 5 {
		if tokens[5] == "*" || tokens[5] == ">" || !isAgentHashToken(tokens[5]) {
			return false, NatsSubjectPermissionErrorInvalidAgentHashToken
		}
	}

	return true, NatsSubjectPermissionErrorNone
}

// TryAdmitSubject validates one concrete subject
// for admission into the closed v1 taxonomy: bounded grammar, control
// namespace, strict ASCII tokens (customer-provided text never becomes a
// subject token), and a fixed agent-hash token inside the host-agent family.
func (natsSubjectTaxonomy) TryAdmitSubject(subject string) (bool, NatsSubjectAdmissionError) {
	if _, err := ConcreteSubjectTryParse(subject, taxonomyGrammarLimits); err != SubjectGrammarErrorNone {
		return false, NatsSubjectAdmissionErrorMalformedSubject
	}

	tokens := strings.Split(subject, ".")
	if len(tokens) < 3 || tokens[0] != "ts" || tokens[1] != "orch" || tokens[2] != "v1" {
		if isPlatformReservedRoot(tokens[0]) {
			return false, NatsSubjectAdmissionErrorPlatformReserved
		}

		return false, NatsSubjectAdmissionErrorOutsideControlRoot
	}

	if !NatsSubjectTaxonomy.IsControlNamespace(NatsSubjectTaxonomy.Classify(subject)) {
		return false, NatsSubjectAdmissionErrorUnknownNamespace
	}

	for _, token := range tokens {
		if !isAdmissibleSubjectToken(token) {
			return false, NatsSubjectAdmissionErrorCustomerTextInSubject
		}
	}

	if len(tokens) > 4 &&
		tokens[3] != NatsSubjectTaxonomy.GlobalScopeToken() &&
		tokens[4] == NatsSubjectTaxonomy.RegionalAgentPrefixSegment() &&
		len(tokens) > 5 &&
		!isAgentHashToken(tokens[5]) {
		return false, NatsSubjectAdmissionErrorInvalidAgentHashToken
	}

	return true, NatsSubjectAdmissionErrorNone
}

// ManifestValidationViolations lists every
// disagreement between the checked-in protocol manifest and the compiled
// taxonomy. An empty list is the contract: the closed family set is identical
// in both directions.
func (natsSubjectTaxonomy) ManifestValidationViolations() []string {
	manifest := ProtocolManifestLoaded()
	violations := []string{}

	if manifest.Root != NatsSubjectTaxonomy.Root() {
		violations = append(violations,
			"The manifest root '"+manifest.Root+"' is not the canonical root '"+NatsSubjectTaxonomy.Root()+"'.")
	}

	if len(manifest.ReservedRegionTokens) != 1 ||
		manifest.ReservedRegionTokens[0] != NatsSubjectTaxonomy.GlobalScopeToken() {
		violations = append(violations,
			"The manifest region-token reservations are not exactly the reserved global scope token.")
	}

	declared := map[string]struct{}{}
	for _, family := range declaredTaxonomyFamilies {
		declared[family.pattern] = struct{}{}
	}

	manifestPatterns := map[string]struct{}{}
	for _, family := range manifest.SubjectFamilies {
		manifestPatterns[family.Pattern] = struct{}{}
	}

	for pattern := range declared {
		if _, present := manifestPatterns[pattern]; !present {
			violations = append(violations, "The manifest is missing the closed subject family '"+pattern+"'.")
		}
	}

	for _, family := range manifest.SubjectFamilies {
		if _, declaredPattern := declared[family.Pattern]; !declaredPattern {
			violations = append(violations, "The manifest declares the unknown subject family '"+family.Pattern+"'.")
		}
	}

	for _, family := range manifest.SubjectFamilies {
		if !strings.HasPrefix(family.Pattern, NatsSubjectTaxonomy.Root()+".") {
			violations = append(violations, "The manifest family '"+family.Pattern+"' does not live under the v1 root.")
		}
	}

	var agentFamily *ProtocolSubjectFamily
	for index := range manifest.SubjectFamilies {
		family := manifest.SubjectFamilies[index]
		if family.Scope == ProtocolSubjectFamilyScopeRegional && family.Family == NatsSubjectTaxonomy.RegionalAgentPrefixSegment() {
			if agentFamily != nil {
				// Exactly one regional agent family may exist; duplicates are a bug.
				panic("Sequence contains more than one matching element")
			}

			agentFamily = &manifest.SubjectFamilies[index]
		}
	}

	if agentFamily == nil || !agentFamily.AgentHashToken ||
		!strings.Contains(agentFamily.Pattern, "."+NatsSubjectTaxonomy.AgentHashPlaceholderToken()+".>") {
		violations = append(violations, "The manifest agent family does not pin the admitted-agent hash token.")
	}

	return violations
}

// isValidCellToken reports whether cell is a valid cell token. It exists so
// this package does not import the control package that owns the root files.
func isValidCellToken(cell string) bool { return cellTokenRuleIsValid(cell) }

// isAgentHashToken reports whether token is a fixed-length lowercase hex
// agent-hash token.
func isAgentHashToken(token string) bool {
	if len(token) != NatsSubjectTaxonomy.AgentHashTokenLength() {
		return false
	}

	for index := 0; index < len(token); index++ {
		character := token[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}

	return true
}

// isPlatformReservedRoot reports whether token starts with a NATS-reserved
// root character ($, _, #).
func isPlatformReservedRoot(token string) bool {
	return len(token) > 0 && (token[0] == '$' || token[0] == '_' || token[0] == '#')
}

// cellTokenRuleIsValid reports whether cell is
// a 1..63 character lowercase DNS-style token that neither
// starts nor ends with a dash.
func cellTokenRuleIsValid(cell string) bool {
	if len(cell) < 1 || len(cell) > 63 {
		return false
	}

	if cell[0] == '-' || cell[len(cell)-1] == '-' {
		return false
	}

	for index := 0; index < len(cell); index++ {
		character := cell[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}

	return true
}

type declaredFamily struct {
	scope   ProtocolSubjectFamilyScope
	family  string
	pattern string
}

var declaredTaxonomyFamilies = []declaredFamily{
	{ProtocolSubjectFamilyScopeGlobal, NatsSubjectTaxonomy.DesiredFamilySegment(),
		NatsSubjectTaxonomy.GlobalRoot() + "." + NatsSubjectTaxonomy.DesiredFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeGlobal, NatsSubjectTaxonomy.ReleaseFamilySegment(),
		NatsSubjectTaxonomy.GlobalRoot() + "." + NatsSubjectTaxonomy.ReleaseFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeGlobal, NatsSubjectTaxonomy.QueryFamilySegment(),
		NatsSubjectTaxonomy.GlobalRoot() + "." + NatsSubjectTaxonomy.QueryFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeRegional, NatsSubjectTaxonomy.DesiredFamilySegment(),
		NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.RegionPlaceholderToken() + "." +
			NatsSubjectTaxonomy.DesiredFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeRegional, NatsSubjectTaxonomy.CommandFamilySegment(),
		NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.RegionPlaceholderToken() + "." +
			NatsSubjectTaxonomy.CommandFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeRegional, NatsSubjectTaxonomy.ObservationFamilySegment(),
		NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.RegionPlaceholderToken() + "." +
			NatsSubjectTaxonomy.ObservationFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeRegional, NatsSubjectTaxonomy.OperationFamilySegment(),
		NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.RegionPlaceholderToken() + "." +
			NatsSubjectTaxonomy.OperationFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeRegional, NatsSubjectTaxonomy.QueryFamilySegment(),
		NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.RegionPlaceholderToken() + "." +
			NatsSubjectTaxonomy.QueryFamilySegment() + ".>"},
	{ProtocolSubjectFamilyScopeRegional, NatsSubjectTaxonomy.RegionalAuditPrefixSegment(),
		NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.RegionPlaceholderToken() + "." +
			NatsSubjectTaxonomy.RegionalAuditPrefixSegment() + ".>"},
	{ProtocolSubjectFamilyScopeRegional, NatsSubjectTaxonomy.RegionalAgentPrefixSegment(),
		NatsSubjectTaxonomy.Root() + "." + NatsSubjectTaxonomy.RegionPlaceholderToken() + "." +
			NatsSubjectTaxonomy.RegionalAgentPrefixSegment() + "." +
			NatsSubjectTaxonomy.AgentHashPlaceholderToken() + ".>"},
}

func isClosedFamilySegment(isGlobal bool, family string) bool {
	if isGlobal {
		switch family {
		case NatsSubjectTaxonomy.DesiredFamilySegment(),
			NatsSubjectTaxonomy.ReleaseFamilySegment(),
			NatsSubjectTaxonomy.QueryFamilySegment():
			return true
		default:
			return false
		}
	}

	switch family {
	case NatsSubjectTaxonomy.DesiredFamilySegment(),
		NatsSubjectTaxonomy.CommandFamilySegment(),
		NatsSubjectTaxonomy.ObservationFamilySegment(),
		NatsSubjectTaxonomy.OperationFamilySegment(),
		NatsSubjectTaxonomy.QueryFamilySegment(),
		NatsSubjectTaxonomy.RegionalAuditPrefixSegment(),
		NatsSubjectTaxonomy.RegionalAgentPrefixSegment():
		return true
	default:
		return false
	}
}

func requireSubjectToken(value, name string) (string, error) {
	if len(value) >= 1 && len(value) <= 128 && isSubjectTokenText(value) {
		return value, nil
	}

	return "", errors.New("The " + name + " is not a bounded subject token. (Parameter '" + name + "')")
}

func isSubjectTokenText(value string) bool {
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}

		return false
	}

	return true
}

func requireNonce(value string, name string) (string, error) {
	if len(value) == 32 && isAsciiHex(value) {
		return value, nil
	}

	return "", errors.New("The " + name + " is not a 32-character hex nonce. (Parameter '" + name + "')")
}

func isAsciiHex(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}

	return true
}

func withRegionalRoot(cell, suffix string) (string, error) {
	root, err := NatsSubjectTaxonomy.RegionalRoot(cell)
	if err != nil {
		return "", err
	}

	return root + suffix, nil
}

func isAdmissibleSubjectToken(token string) bool {
	if len(token) > 128 {
		return false
	}

	for _, character := range token {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}

		return false
	}

	return true
}

func createGrammarLimits() *SubjectGrammarLimits {
	limits, ok := SubjectGrammarLimitsTryCreate(512, 16, 128, 256)
	if !ok || limits == nil {
		panic("The canonical NATS subject grammar limits are invalid.")
	}

	return limits
}

// NatsSubjectNamespace is the closed set
// of subject namespaces. Seven of the eight business namespaces are control
// subjects; the eighth — ProductPlane — names the separate product trust
// plane, which the control taxonomy never defines subjects for, and
// PlatformReserved covers NATS-reserved API subjects.
type NatsSubjectNamespace int

const (
	NatsSubjectNamespaceUnspecified           NatsSubjectNamespace = 0
	NatsSubjectNamespaceGlobalAuthority       NatsSubjectNamespace = 1
	NatsSubjectNamespaceGlobalDirectory       NatsSubjectNamespace = 2
	NatsSubjectNamespaceRegionalControl       NatsSubjectNamespace = 3
	NatsSubjectNamespaceAgent                 NatsSubjectNamespace = 4
	NatsSubjectNamespaceContinuousIntegration NatsSubjectNamespace = 5
	NatsSubjectNamespaceOperations            NatsSubjectNamespace = 6
	NatsSubjectNamespaceAudit                 NatsSubjectNamespace = 7
	NatsSubjectNamespaceProductPlane          NatsSubjectNamespace = 8
	NatsSubjectNamespacePlatformReserved      NatsSubjectNamespace = 9
	NatsSubjectNamespaceUnknown               NatsSubjectNamespace = 10
)

func (ns NatsSubjectNamespace) String() string {
	switch ns {
	case NatsSubjectNamespaceGlobalAuthority:
		return "GlobalAuthority"
	case NatsSubjectNamespaceGlobalDirectory:
		return "GlobalDirectory"
	case NatsSubjectNamespaceRegionalControl:
		return "RegionalControl"
	case NatsSubjectNamespaceAgent:
		return "Agent"
	case NatsSubjectNamespaceContinuousIntegration:
		return "ContinuousIntegration"
	case NatsSubjectNamespaceOperations:
		return "Operations"
	case NatsSubjectNamespaceAudit:
		return "Audit"
	case NatsSubjectNamespaceProductPlane:
		return "ProductPlane"
	case NatsSubjectNamespacePlatformReserved:
		return "PlatformReserved"
	case NatsSubjectNamespaceUnknown:
		return "Unknown"
	default:
		return strconv.Itoa(int(ns))
	}
}

// NatsSubjectPermissionError classifies why
// one permission pattern is not a closed v1 control-family permission.
type NatsSubjectPermissionError int

const (
	NatsSubjectPermissionErrorNone                  NatsSubjectPermissionError = 0
	NatsSubjectPermissionErrorMalformedPattern      NatsSubjectPermissionError = 1
	NatsSubjectPermissionErrorOutsideControlRoot    NatsSubjectPermissionError = 2
	NatsSubjectPermissionErrorWildcardInScopeToken  NatsSubjectPermissionError = 3
	NatsSubjectPermissionErrorWildcardInFamilyToken NatsSubjectPermissionError = 4
	NatsSubjectPermissionErrorInvalidRegionToken    NatsSubjectPermissionError = 5
	NatsSubjectPermissionErrorUnknownFamily         NatsSubjectPermissionError = 6
	NatsSubjectPermissionErrorInvalidAgentHashToken NatsSubjectPermissionError = 7
	NatsSubjectPermissionErrorPlatformReserved      NatsSubjectPermissionError = 8
)

func (e NatsSubjectPermissionError) String() string {
	switch e {
	case NatsSubjectPermissionErrorNone:
		return "None"
	case NatsSubjectPermissionErrorMalformedPattern:
		return "MalformedPattern"
	case NatsSubjectPermissionErrorOutsideControlRoot:
		return "OutsideControlRoot"
	case NatsSubjectPermissionErrorWildcardInScopeToken:
		return "WildcardInScopeToken"
	case NatsSubjectPermissionErrorWildcardInFamilyToken:
		return "WildcardInFamilyToken"
	case NatsSubjectPermissionErrorInvalidRegionToken:
		return "InvalidRegionToken"
	case NatsSubjectPermissionErrorUnknownFamily:
		return "UnknownFamily"
	case NatsSubjectPermissionErrorInvalidAgentHashToken:
		return "InvalidAgentHashToken"
	case NatsSubjectPermissionErrorPlatformReserved:
		return "PlatformReserved"
	default:
		return strconv.Itoa(int(e))
	}
}

// NatsSubjectAdmissionError classifies why
// one concrete subject is not admissible into the closed v1 taxonomy.
type NatsSubjectAdmissionError int

const (
	NatsSubjectAdmissionErrorNone                  NatsSubjectAdmissionError = 0
	NatsSubjectAdmissionErrorMalformedSubject      NatsSubjectAdmissionError = 1
	NatsSubjectAdmissionErrorOutsideControlRoot    NatsSubjectAdmissionError = 2
	NatsSubjectAdmissionErrorUnknownNamespace      NatsSubjectAdmissionError = 3
	NatsSubjectAdmissionErrorCustomerTextInSubject NatsSubjectAdmissionError = 4
	NatsSubjectAdmissionErrorInvalidAgentHashToken NatsSubjectAdmissionError = 5
	NatsSubjectAdmissionErrorPlatformReserved      NatsSubjectAdmissionError = 6
)

func (e NatsSubjectAdmissionError) String() string {
	switch e {
	case NatsSubjectAdmissionErrorNone:
		return "None"
	case NatsSubjectAdmissionErrorMalformedSubject:
		return "MalformedSubject"
	case NatsSubjectAdmissionErrorOutsideControlRoot:
		return "OutsideControlRoot"
	case NatsSubjectAdmissionErrorUnknownNamespace:
		return "UnknownNamespace"
	case NatsSubjectAdmissionErrorCustomerTextInSubject:
		return "CustomerTextInSubject"
	case NatsSubjectAdmissionErrorInvalidAgentHashToken:
		return "InvalidAgentHashToken"
	case NatsSubjectAdmissionErrorPlatformReserved:
		return "PlatformReserved"
	default:
		return strconv.Itoa(int(e))
	}
}
