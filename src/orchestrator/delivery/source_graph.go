package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const MaximumGraphRepositories = 64
const maximumDeployDescriptorDepth = 64

var (
	deployReleaseTestExclusionPattern      = regexp.MustCompile(`(?i)(?:!=|!~)|^(?:--?|/)(?:exclude(?:-category)?|skip|ignore|notrait|not-trait|list-tests)(?:$|[=:])`)
	deployReleaseTestFilterPattern         = regexp.MustCompile(`(?i)^(?:--?|/)(?:filter|treenode-filter|test-case-filter|where)(?:[=:](?P<value>.*))?$`)
	deployPositiveIntegrationFilterPattern = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:Test)?Category\s*(?:=|~)\s*Integration(?:[^A-Za-z0-9]|$)`)
	deployReservedCandidateTestArgPattern  = regexp.MustCompile(`(?i)^(?:--?|/)(?:ignore-exit-code|list-tests|help|report-trx|report-trx-filename|results-directory|minimum-expected-tests|no-ansi|no-progress)(?:$|[=:])`)
)

// RepositorySource is the narrow seam used by the graph; tests and alternate
// Forgejo transports can supply it without constructing an HTTP client.
type RepositorySource interface {
	Resolve(context.Context, string) (ResolvedRevision, error)
	PollBranch(context.Context, string) (BranchObservation, error)
	ReadFile(context.Context, string, string, int) (SourceFile, error)
	ReadArchive(context.Context, ResolvedRevision) (SourceArchive, error)
}
type SourceSnapshot struct {
	Files        []SourceFile
	Sources      []ResolvedRevision
	Observations []BranchObservation
}
type RepositorySourceGraph struct {
	Root    string
	Sources map[string]RepositorySource
}

// These descriptor types mirror the JSON field shapes consumed by the Go
// ts-deploy CLI. The orchestrator only needs the repository identity, but it
// still rejects a descriptor whose known fields could not be consumed by that
// CLI without a type error.
type deployDescriptor struct {
	Repository      string                        `json:"repository"`
	Dependencies    []deployDependencyEdge        `json:"dependencies"`
	PrProfiles      []deployProfile               `json:"prProfiles"`
	ReleaseProfiles []deployProfile               `json:"releaseProfiles"`
	BuildTargets    []deployProfile               `json:"buildTargets"`
	Candidate       *deployCandidateStrategy      `json:"candidate"`
	Promotion       *deployPromotionConfiguration `json:"promotion"`
	Services        []json.RawMessage             `json:"services"`
}

type deployDependencyEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

type deployProfile struct {
	Name                  string                      `json:"name"`
	ResourceWeight        *string                     `json:"resourceWeight"`
	Commands              []deployWorkflowCommand     `json:"commands"`
	Required              *bool                       `json:"required"`
	OutputPath            *string                     `json:"outputPath"`
	CandidateTarget       *string                     `json:"candidateTarget"`
	Entrypoint            *string                     `json:"entrypoint"`
	Arguments             []string                    `json:"arguments"`
	MinimumExpectedTests  *int                        `json:"minimumExpectedTests"`
	CandidateDependencies []deployCandidateDependency `json:"candidateDependencies"`
}

type deployCandidateDependency struct {
	Name            string   `json:"name"`
	Repository      string   `json:"repository"`
	Target          string   `json:"target"`
	InputPath       string   `json:"inputPath"`
	RequiredFiles   []string `json:"requiredFiles"`
	ExecutableFiles []string `json:"executableFiles"`
}

type deployWorkflowCommand struct {
	Description      string   `json:"description"`
	Command          string   `json:"command"`
	Arguments        []string `json:"arguments"`
	WorkingDirectory *string  `json:"workingDirectory"`
}

type deployCandidateStrategy struct {
	GenericPackageName *string `json:"genericPackageName"`
	RetentionDays      int     `json:"retentionDays"`
}

type deployPromotionConfiguration struct {
	Strategy  string   `json:"strategy"`
	Endpoints []string `json:"endpoints"`
}

func (g *RepositorySourceGraph) Close() error {
	if g == nil {
		return nil
	}
	var first error
	for _, source := range g.Sources {
		if client, ok := source.(*SourceClient); ok {
			if err := client.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func NewSourceGraph(root string, sources map[string]RepositorySource) (*RepositorySourceGraph, error) {
	if !ValidRepository(root) || len(sources) == 0 || len(sources) > MaximumGraphRepositories {
		return nil, errors.New("invalid source graph")
	}
	copyMap := map[string]RepositorySource{}
	for repo, client := range sources {
		if !ValidRepository(repo) || client == nil {
			return nil, errors.New("invalid source graph client")
		}
		copyMap[repo] = client
	}
	if copyMap[root] == nil {
		return nil, errors.New("source graph omits root")
	}
	return &RepositorySourceGraph{Root: root, Sources: copyMap}, nil
}
func (g *RepositorySourceGraph) Snapshot(ctx context.Context, event *WebhookEnvelope, branch string, exactRoot bool) (SourceSnapshot, error) {
	if ctx == nil {
		return SourceSnapshot{}, errors.New("snapshot context is required")
	}
	if g == nil || event == nil || event.Repository != g.Root || g.Sources[g.Root] == nil || branch != "develop" && branch != "main" {
		return SourceSnapshot{}, errors.New("trigger is outside source graph root")
	}
	repos := make([]string, 0, len(g.Sources))
	for r := range g.Sources {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	out := SourceSnapshot{}
	for _, repo := range repos {
		if err := ctx.Err(); err != nil {
			return SourceSnapshot{}, err
		}
		var rev ResolvedRevision
		var obs BranchObservation
		var e error
		if repo == g.Root && !exactRoot {
			rev, e = g.Sources[repo].Resolve(ctx, event.Revision)
		} else {
			obs, e = g.Sources[repo].PollBranch(ctx, branch)
			if e == nil && (!obs.Protected || obs.Revision.Repository != repo || exactRoot && repo == g.Root && !equalFold(obs.Revision.Commit, event.Revision)) {
				e = errors.New("source branch is unprotected or changed")
			}
			rev = obs.Revision
		}
		if e != nil {
			return SourceSnapshot{}, e
		}
		file, e := g.Sources[repo].ReadFile(ctx, rev.Commit, CIDescriptorPath, MaximumSourceFileBytes)
		if e != nil {
			return SourceSnapshot{}, e
		}
		if file.Repository != repo || file.Commit != rev.Commit || file.Path != CIDescriptorPath {
			return SourceSnapshot{}, errors.New("source descriptor identity changed")
		}
		out.Files = append(out.Files, file)
		out.Sources = append(out.Sources, rev)
		if obs.Branch != "" {
			out.Observations = append(out.Observations, obs)
		}
	}
	return out, nil
}
func (g *RepositorySourceGraph) ReadArchive(ctx context.Context, rev ResolvedRevision) (SourceArchive, error) {
	if g == nil || g.Sources[rev.Repository] == nil {
		return SourceArchive{}, errors.New("archive repository is outside source graph")
	}
	return g.Sources[rev.Repository].ReadArchive(ctx, rev)
}
func parseDescriptor(content []byte) (string, []string, error) {
	var d deployDescriptor
	if len(content) == 0 || len(content) > MaximumSourceFileBytes || duplicateDeployDescriptorProperties(content) {
		return "", nil, errors.New("invalid CI descriptor")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(&struct{}{}) != io.EOF || !ValidRepository(d.Repository) {
		return "", nil, errors.New("invalid CI descriptor")
	}
	if err := validateDeployDescriptor(d); err != nil {
		return "", nil, err
	}
	// deploy.json dependencies select profiles from changed paths within one
	// repository. Repository membership comes from RepositorySourceGraph, so
	// these path edges must never be reinterpreted as repository dependencies.
	return d.Repository, nil, nil
}

// duplicateDeployDescriptorProperties rejects malformed JSON before the typed
// decoder can apply last-value-wins behavior. Deploy's JSON boundary compares
// member names case-insensitively and caps nesting at 64, so this boundary
// applies the same rules to every object, including arbitrary service values.
func duplicateDeployDescriptorProperties(content []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(content))
	token, err := decoder.Token()
	if err != nil || deployDescriptorValueHasDuplicate(decoder, token, 1) {
		return true
	}
	_, err = decoder.Token()
	return err == nil
}

func deployDescriptorValueHasDuplicate(decoder *json.Decoder, token json.Token, depth int) bool {
	if depth > maximumDeployDescriptorDepth {
		return true
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false
	}
	switch delim {
	case '[':
		for {
			value, err := decoder.Token()
			if err != nil {
				return true
			}
			if value == json.Delim(']') {
				return false
			}
			if deployDescriptorValueHasDuplicate(decoder, value, depth+1) {
				return true
			}
		}
	case '{':
		seen := map[string]struct{}{}
		for {
			key, err := decoder.Token()
			if err != nil {
				return true
			}
			if key == json.Delim('}') {
				return false
			}
			name, ok := key.(string)
			if !ok {
				return true
			}
			canonical := strings.ToLower(name)
			if _, ok := seen[canonical]; ok {
				return true
			}
			seen[canonical] = struct{}{}
			value, err := decoder.Token()
			if err != nil || deployDescriptorValueHasDuplicate(decoder, value, depth+1) {
				return true
			}
		}
	default:
		return true
	}
}

func validateDeployDescriptor(descriptor deployDescriptor) error {
	for _, dependency := range descriptor.Dependencies {
		if !validDeployDependencySource(dependency.Source) || !validDeployProfileName(dependency.Target) || strings.TrimSpace(dependency.Reason) == "" {
			return errors.New("invalid CI dependency edge")
		}
	}
	for _, profiles := range [][]deployProfile{descriptor.PrProfiles, descriptor.ReleaseProfiles, descriptor.BuildTargets} {
		seen := map[string]struct{}{}
		for _, profile := range profiles {
			if !validDeployProfileName(profile.Name) {
				return errors.New("invalid CI profile")
			}
			name := strings.ToLower(profile.Name)
			if _, ok := seen[name]; ok {
				return errors.New("duplicate CI profile")
			}
			seen[name] = struct{}{}
			if profile.ResourceWeight != nil && *profile.ResourceWeight != "light" && *profile.ResourceWeight != "medium" && *profile.ResourceWeight != "heavy" {
				return errors.New("invalid CI profile resource weight")
			}
			for _, command := range profile.Commands {
				if strings.TrimSpace(command.Description) == "" || strings.TrimSpace(command.Command) == "" || command.Arguments == nil {
					return errors.New("invalid CI workflow command")
				}
				if command.WorkingDirectory != nil && *command.WorkingDirectory != "" && !validDeployPath(*command.WorkingDirectory, false) {
					return errors.New("invalid CI workflow working directory")
				}
			}
		}
	}
	for _, profile := range descriptor.BuildTargets {
		if profile.Required == nil || *profile.Required {
			if len(profile.Commands) == 0 {
				return errors.New("invalid CI build target commands")
			}
		}
		if profile.OutputPath != nil && !validDeployPath(*profile.OutputPath, true) {
			return errors.New("invalid CI build output path")
		}
		if profile.CandidateTarget != nil || profile.Entrypoint != nil || profile.Arguments != nil || profile.MinimumExpectedTests != nil || len(profile.CandidateDependencies) > 0 {
			return errors.New("invalid CI build target contract")
		}
	}
	for _, profile := range descriptor.PrProfiles {
		if profile.Required == nil || *profile.Required {
			if len(profile.Commands) == 0 {
				return errors.New("invalid CI PR profile commands")
			}
		}
		if profile.OutputPath != nil || profile.CandidateTarget != nil || profile.Entrypoint != nil || profile.Arguments != nil || profile.MinimumExpectedTests != nil || len(profile.CandidateDependencies) > 0 {
			return errors.New("invalid CI PR profile contract")
		}
	}
	for _, profile := range descriptor.ReleaseProfiles {
		if profile.OutputPath != nil {
			return errors.New("invalid CI release profile contract")
		}
		if profile.Required != nil && !*profile.Required {
			return errors.New("invalid CI release profile requirement")
		}
		candidateBound := profile.CandidateTarget != nil || profile.Entrypoint != nil || profile.Arguments != nil || profile.MinimumExpectedTests != nil
		if candidateBound {
			if len(profile.Commands) > 0 || profile.CandidateTarget == nil || strings.TrimSpace(*profile.CandidateTarget) == "" || profile.Entrypoint == nil || strings.TrimSpace(*profile.Entrypoint) == "" || profile.Arguments == nil || profile.MinimumExpectedTests == nil || *profile.MinimumExpectedTests < 1 || *profile.MinimumExpectedTests > 1_000_000 {
				return errors.New("invalid CI candidate release profile")
			}
			if !validDeployPath(*profile.Entrypoint, false) {
				return errors.New("invalid CI release entrypoint")
			}
			for _, argument := range profile.Arguments {
				if len(argument) > 4_096 || strings.ContainsFunc(argument, unicode.IsControl) {
					return errors.New("invalid CI release argument")
				}
				if deployReservedCandidateTestArgPattern.MatchString(argument) {
					return errors.New("invalid CI candidate release argument")
				}
			}
			var target *deployProfile
			for index := range descriptor.BuildTargets {
				if descriptor.BuildTargets[index].Name == *profile.CandidateTarget {
					target = &descriptor.BuildTargets[index]
					break
				}
			}
			if target == nil || target.OutputPath == nil || !validDeployPath(*target.OutputPath, true) {
				return errors.New("invalid CI candidate target")
			}
			if err := validateDeployCandidateDependencies(profile.CandidateDependencies, *target); err != nil {
				return err
			}
			continue
		}
		if len(profile.CandidateDependencies) > 0 {
			return errors.New("invalid CI source release profile")
		}
		if len(profile.Commands) == 0 {
			return errors.New("invalid CI release profile commands")
		}
		for _, command := range profile.Commands {
			if strings.TrimSpace(command.Description) == "" || command.Arguments == nil {
				return errors.New("invalid CI release command")
			}
			if err := validateDeployReleaseArguments(command.Arguments); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateDeployReleaseArguments(arguments []string) error {
	for index, argument := range arguments {
		if deployReleaseTestExclusionPattern.MatchString(argument) {
			return errors.New("invalid CI release test exclusion")
		}
		match := deployReleaseTestFilterPattern.FindStringSubmatchIndex(argument)
		if match == nil {
			continue
		}
		value := ""
		if match[2] >= 0 {
			value = argument[match[2]:match[3]]
		} else if index+1 < len(arguments) {
			value = arguments[index+1]
		}
		if deployReleaseTestExclusionPattern.MatchString(value) || !deployPositiveIntegrationFilterPattern.MatchString(value) {
			return errors.New("invalid CI release test filter")
		}
	}
	return nil
}

func validateDeployCandidateDependencies(dependencies []deployCandidateDependency, target deployProfile) error {
	if len(dependencies) > 32 || target.OutputPath == nil || !validDeployPath(*target.OutputPath, true) {
		return errors.New("invalid CI candidate dependencies")
	}
	names := map[string]struct{}{}
	environmentNames := map[string]struct{}{}
	inputPaths := map[string]struct{}{}
	for _, dependency := range dependencies {
		if !validDeployProfileName(dependency.Name) || !validDeployProfileName(dependency.Repository) || !validDeployProfileName(dependency.Target) || !validDeployPath(dependency.InputPath, true) || !strings.HasPrefix(dependency.InputPath, "artifacts/dependencies/") {
			return errors.New("invalid CI candidate dependency")
		}
		name := strings.ToLower(dependency.Name)
		if _, ok := names[name]; ok {
			return errors.New("duplicate CI candidate dependency")
		}
		environmentName := candidateDependencyEnvironmentName(dependency.Name)
		if _, ok := environmentNames[environmentName]; ok {
			return errors.New("ambiguous CI candidate dependency")
		}
		names[name] = struct{}{}
		environmentNames[environmentName] = struct{}{}
		if _, ok := inputPaths[dependency.InputPath]; ok || deployPathsOverlap(dependency.InputPath, *target.OutputPath) {
			return errors.New("overlapping CI candidate dependency path")
		}
		inputPaths[dependency.InputPath] = struct{}{}
		if len(dependency.RequiredFiles) < 1 || len(dependency.RequiredFiles) > 64 || dependency.ExecutableFiles == nil || len(dependency.ExecutableFiles) > 64 {
			return errors.New("invalid CI candidate dependency files")
		}
		required := map[string]struct{}{}
		for _, path := range dependency.RequiredFiles {
			if !validDeployPath(path, false) {
				return errors.New("invalid CI candidate dependency file")
			}
			if _, ok := required[path]; ok {
				return errors.New("duplicate CI candidate dependency file")
			}
			required[path] = struct{}{}
		}
		executable := map[string]struct{}{}
		for _, path := range dependency.ExecutableFiles {
			if !validDeployPath(path, false) {
				return errors.New("invalid CI candidate executable file")
			}
			if _, ok := required[path]; !ok {
				return errors.New("CI executable file is not required")
			}
			if _, ok := executable[path]; ok {
				return errors.New("duplicate CI candidate executable file")
			}
			executable[path] = struct{}{}
		}
	}
	for left := range inputPaths {
		for right := range inputPaths {
			if left != right && deployPathsOverlap(left, right) {
				return errors.New("overlapping CI candidate dependency paths")
			}
		}
	}
	return nil
}

func candidateDependencyEnvironmentName(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if isDeployAsciiLetterOrDigit(character) {
			builder.WriteRune(unicode.ToUpper(character))
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func deployPathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func validDeployProfileName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if (index == 0 && !isDeployAsciiLetterOrDigit(character)) || (!isDeployAsciiLetterOrDigit(character) && character != '.' && character != '_' && character != '-') {
			return false
		}
	}
	return true
}

func isDeployAsciiLetterOrDigit(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func validDeployDependencySource(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.ContainsAny(value, "\\\r\n") && !strings.ContainsFunc(value, unicode.IsSpace) && !strings.Contains(value, "..")
}

func validDeployPath(value string, requireArtifactsPrefix bool) bool {
	if strings.TrimSpace(value) == "" || len(value) > 512 || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.Contains(value, ":") || strings.ContainsFunc(value, func(character rune) bool { return unicode.IsControl(character) || unicode.IsSpace(character) }) {
		return false
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return !requireArtifactsPrefix || parts[0] == "artifacts"
}
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'F' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'F' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
