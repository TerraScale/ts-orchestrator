// Port of src/TerraScale.Orchestrator/Protocol/ProtocolManifest.cs. The
// checked-in manifest bytes are embedded from protocol-manifest.json, a
// byte-identical copy of the C# embedded resource.
package protocol

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
	"unicode"
)

//go:embed protocol-manifest.json
var embeddedProtocolManifest []byte

// ProtocolSubjectFamilyScope mirrors the ProtocolSubjectFamilyScope enum.
type ProtocolSubjectFamilyScope int

const (
	ProtocolSubjectFamilyScopeUnspecified ProtocolSubjectFamilyScope = 0
	ProtocolSubjectFamilyScopeGlobal      ProtocolSubjectFamilyScope = 1
	ProtocolSubjectFamilyScopeRegional    ProtocolSubjectFamilyScope = 2
)

// ProtocolSubjectFamily is one closed subject family of the checked-in
// protocol manifest. Pattern is the manifest-facing template: regional
// families carry the <region> placeholder and the agent family additionally
// carries the <agent-hash> placeholder.
type ProtocolSubjectFamily struct {
	Scope          ProtocolSubjectFamilyScope
	Family         string
	Pattern        string
	AgentHashToken bool
}

// IsWellFormed mirrors the internal family well-formedness rule.
func (f ProtocolSubjectFamily) IsWellFormed() bool {
	if f.Scope != ProtocolSubjectFamilyScopeGlobal && f.Scope != ProtocolSubjectFamilyScopeRegional {
		return false
	}

	if len(f.Family) < 1 || len(f.Family) > 32 {
		return false
	}

	for _, character := range f.Family {
		if (character < 'a' || character > 'z') && character != '-' {
			return false
		}
	}

	if len(f.Pattern) < 1 || len(f.Pattern) > 128 {
		return false
	}

	if strings.IndexFunc(f.Pattern, func(r rune) bool { return isUnicodeWhitespace(r) }) >= 0 {
		return false
	}

	return !f.AgentHashToken || f.Scope == ProtocolSubjectFamilyScopeRegional
}

// ProtocolAccountKindGrants is the standing permission grant template of one
// account kind, as declared by the protocol manifest. Templates substitute
// <region> and <agent-hash> when a scope is instantiated. BreakGlass kinds
// hold no standing grants at all.
type ProtocolAccountKindGrants struct {
	Kind           string
	RegionScoped   bool
	AgentHashScoped bool
	PlatformOnly   bool
	ReadOnly       bool
	BreakGlass     bool
	Publish        []string
	Subscribe      []string
}

// IsWellFormed mirrors the internal grants well-formedness rule.
func (g ProtocolAccountKindGrants) IsWellFormed() bool {
	if len(g.Kind) < 1 || len(g.Kind) > 64 {
		return false
	}

	for _, character := range g.Kind {
		if (character < 'a' || character > 'z') && character != '-' {
			return false
		}
	}

	if len(g.Publish) > 64 || len(g.Subscribe) > 64 {
		return false
	}

	for _, pattern := range g.Publish {
		if !isBoundedGrantPattern(pattern) {
			return false
		}
	}

	for _, pattern := range g.Subscribe {
		if !isBoundedGrantPattern(pattern) {
			return false
		}
	}

	if g.BreakGlass && (len(g.Publish) != 0 || len(g.Subscribe) != 0) {
		return false
	}

	if g.ReadOnly && len(g.Publish) != 0 {
		return false
	}

	return !g.AgentHashScoped || g.RegionScoped
}

func isBoundedGrantPattern(pattern string) bool {
	if len(pattern) < 1 || len(pattern) > 256 {
		return false
	}

	return strings.IndexFunc(pattern, func(r rune) bool { return isUnicodeWhitespace(r) }) < 0
}

func isUnicodeWhitespace(r rune) bool {
	// unicode.IsSpace mirrors char.IsWhiteSpace: ASCII whitespace, NEL/NBSP,
	// and the Unicode space (Zs) category.
	return unicode.IsSpace(r)
}

// ProtocolManifest is the checked-in protocol manifest: the single source of
// truth for the closed subject-family set and the account-kind grant
// templates. The manifest is embedded into the binary and loaded fail-closed:
// a missing, oversized, malformed, or shape-invalid manifest panics (the C#
// InvalidOperationException thrown out of the lazy loader), never a silent
// fallback to compiled defaults.
type ProtocolManifest struct {
	Name                string
	Version             string
	Root                string
	SupersededRoots     []string
	ReservedRegionTokens []string
	SubjectFamilies     []ProtocolSubjectFamily
	AccountKinds        []ProtocolAccountKindGrants
}

// ManifestResourceName mirrors the C# const naming the embedded resource.
const ManifestResourceName = "TerraScale.Orchestrator.Protocol.protocol-manifest.json"

const (
	maximumManifestBytes = 1024 * 1024
	maximumSubjectFamilies = 64
	maximumAccountKinds    = 32
)

var (
	embeddedManifestOnce sync.Once
	embeddedManifest     *ProtocolManifest
)

// ProtocolManifestLoaded mirrors ProtocolManifest.Loaded: the loaded embedded
// manifest. Loading validates the manifest shape once.
var ProtocolManifestLoaded = func() *ProtocolManifest {
	embeddedManifestOnce.Do(func() {
		embeddedManifest = loadEmbeddedProtocolManifest()
	})
	return embeddedManifest
}

func loadEmbeddedProtocolManifest() *ProtocolManifest {
	if len(embeddedProtocolManifest) > maximumManifestBytes {
		panic("The protocol manifest exceeds the bounded manifest size.")
	}

	dto, err := parseProtocolManifestDto(embeddedProtocolManifest)
	if err != nil {
		panic("The protocol manifest is not valid JSON.")
	}

	return protocolManifestFromDto(dto)
}

func parseProtocolManifestDto(data []byte) (*protocolManifestDto, error) {
	var dto protocolManifestDto
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, err
	}

	return &dto, nil
}

func protocolManifestFromDto(dto *protocolManifestDto) *ProtocolManifest {
	if dto == nil {
		panic("The protocol manifest is empty.")
	}

	if isNullOrWhiteSpaceString(dto.Name) || len(deref(dto.Name)) > 128 ||
		isNullOrWhiteSpaceString(dto.Version) || len(deref(dto.Version)) > 32 ||
		isNullOrWhiteSpaceString(dto.Root) || len(deref(dto.Root)) > 128 ||
		strings.IndexFunc(deref(dto.Root), func(r rune) bool { return isUnicodeWhitespace(r) }) >= 0 ||
		dto.SupersededRoots == nil || len(dto.SupersededRoots) < 1 ||
		anySupersededRootMalformed(dto.SupersededRoots) {
		panic("The protocol manifest header is malformed.")
	}

	reserved := filterReservedRegionTokens(dto.RegionToken)
	if len(reserved) == 0 || hasOrdinalDuplicates(reserved) {
		panic("The protocol manifest region-token reservations are malformed.")
	}

	if dto.SubjectFamilies == nil || len(dto.SubjectFamilies) < 1 || len(dto.SubjectFamilies) > maximumSubjectFamilies ||
		dto.AccountKinds == nil || len(dto.AccountKinds) < 1 || len(dto.AccountKinds) > maximumAccountKinds {
		panic("The protocol manifest family or account tables are out of bounds.")
	}

	families := make([]ProtocolSubjectFamily, len(dto.SubjectFamilies))
	familyKeys := map[ProtocolSubjectFamilyScope]map[string]struct{}{
		ProtocolSubjectFamilyScopeGlobal:   {},
		ProtocolSubjectFamilyScopeRegional: {},
		ProtocolSubjectFamilyScopeUnspecified: {},
	}
	familyPatterns := map[string]struct{}{}
	for index, entry := range dto.SubjectFamilies {
		scope := ProtocolSubjectFamilyScopeUnspecified
		switch deref(entry.Scope) {
		case "global":
			scope = ProtocolSubjectFamilyScopeGlobal
		case "regional":
			scope = ProtocolSubjectFamilyScopeRegional
		}

		family := ProtocolSubjectFamily{
			Scope:          scope,
			Family:         deref(entry.Family),
			Pattern:        deref(entry.Pattern),
			AgentHashToken: entry.AgentHashToken,
		}

		if _, duplicate := familyKeys[family.Scope][family.Family]; !family.IsWellFormed() || duplicate {
			panic("The protocol manifest subject family '" + family.Family + "' is malformed or duplicated.")
		}

		if _, duplicatePattern := familyPatterns[family.Pattern]; duplicatePattern {
			panic("The protocol manifest subject family '" + family.Family + "' is malformed or duplicated.")
		}

		familyKeys[family.Scope][family.Family] = struct{}{}
		familyPatterns[family.Pattern] = struct{}{}
		families[index] = family
	}

	kinds := make([]ProtocolAccountKindGrants, len(dto.AccountKinds))
	kindNames := map[string]struct{}{}
	for index, entry := range dto.AccountKinds {
		grants := ProtocolAccountKindGrants{
			Kind:            deref(entry.Kind),
			RegionScoped:    entry.RegionScoped,
			AgentHashScoped: entry.AgentHashScoped,
			PlatformOnly:    entry.PlatformOnly,
			ReadOnly:        entry.ReadOnly,
			BreakGlass:      entry.BreakGlass,
			Publish:         derefStringSlice(entry.Publish),
			Subscribe:       derefStringSlice(entry.Subscribe),
		}

		if !grants.IsWellFormed() {
			panic("The protocol manifest account kind '" + grants.Kind + "' is malformed or duplicated.")
		}

		if _, duplicate := kindNames[grants.Kind]; duplicate {
			panic("The protocol manifest account kind '" + grants.Kind + "' is malformed or duplicated.")
		}

		kindNames[grants.Kind] = struct{}{}
		kinds[index] = grants
	}

	supersededRoots := make([]string, 0, len(dto.SupersededRoots))
	for _, root := range dto.SupersededRoots {
		if !isNullOrWhiteSpaceString(&root) {
			supersededRoots = append(supersededRoots, root)
		}
	}

	return &ProtocolManifest{
		Name:                 deref(dto.Name),
		Version:              deref(dto.Version),
		Root:                 deref(dto.Root),
		SupersededRoots:      supersededRoots,
		ReservedRegionTokens: reserved,
		SubjectFamilies:      families,
		AccountKinds:         kinds,
	}
}

func filterReservedRegionTokens(regionToken *protocolRegionTokenDto) []string {
	if regionToken == nil || regionToken.ReservedTokens == nil {
		return nil
	}

	reserved := []string{}
	for _, token := range regionToken.ReservedTokens {
		if !isNullOrWhiteSpaceString(&token) && len(token) <= 63 {
			reserved = append(reserved, token)
		}
	}

	return reserved
}

func anySupersededRootMalformed(roots []string) bool {
	for _, root := range roots {
		if isNullOrWhiteSpaceString(&root) || len(root) > 128 {
			return true
		}
	}

	return false
}

func hasOrdinalDuplicates(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return true
		}

		seen[value] = struct{}{}
	}

	return false
}

func isNullOrWhiteSpaceString(value *string) bool {
	return value == nil || strings.TrimSpace(*value) == ""
}

func deref(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func derefStringSlice(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}

// The wire DTOs mirror the C# DTO shapes: camelCase property names and
// nullable strings/lists (System.Text.Json source generation, default options).
type protocolManifestDto struct {
	Name            *string                  `json:"name"`
	Version         *string                  `json:"version"`
	Root            *string                  `json:"root"`
	SupersededRoots []string                 `json:"supersededRoots"`
	RegionToken     *protocolRegionTokenDto  `json:"regionToken"`
	SubjectFamilies []protocolSubjectFamilyDto `json:"subjectFamilies"`
	AccountKinds    []protocolAccountKindDto `json:"accountKinds"`
}

type protocolRegionTokenDto struct {
	ReservedTokens []string `json:"reservedTokens"`
}

type protocolSubjectFamilyDto struct {
	Scope          *string `json:"scope"`
	Family         *string `json:"family"`
	Pattern        *string `json:"pattern"`
	AgentHashToken bool    `json:"agentHashToken"`
}

type protocolAccountKindDto struct {
	Kind            *string  `json:"kind"`
	RegionScoped    bool     `json:"regionScoped"`
	AgentHashScoped bool     `json:"agentHashScoped"`
	PlatformOnly    bool     `json:"platformOnly"`
	ReadOnly        bool     `json:"readOnly"`
	BreakGlass      bool     `json:"breakGlass"`
	Publish         []string `json:"publish"`
	Subscribe       []string `json:"subscribe"`
}
