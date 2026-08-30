package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
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

func NewSourceGraph(root string, sources map[string]RepositorySource) (*RepositorySourceGraph, error) {
	if !ValidRepository(root) || len(sources) == 0 {
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
	if g == nil || event == nil || event.Repository != g.Root || g.Sources[g.Root] == nil {
		return SourceSnapshot{}, errors.New("trigger is outside source graph root")
	}
	repos := make([]string, 0, len(g.Sources))
	for r := range g.Sources {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	out := SourceSnapshot{}
	for _, repo := range repos {
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
	var d struct {
		Repository             string `json:"repository"`
		RepositoryDependencies []struct {
			Repository string `json:"repository"`
		} `json:"repositoryDependencies"`
	}
	if e := json.Unmarshal(content, &d); e != nil || !ValidRepository(d.Repository) {
		return "", nil, errors.New("invalid CI descriptor")
	}
	deps := make([]string, 0, len(d.RepositoryDependencies))
	for _, dep := range d.RepositoryDependencies {
		if !ValidRepository(dep.Repository) {
			return "", nil, errors.New("invalid CI dependency")
		}
		deps = append(deps, dep.Repository)
	}
	return d.Repository, deps, nil
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
