package releaseattest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	apiBase      = "https://api.github.com/repos/" + Repository
	listLimit    = 4 << 20
	compareLimit = 1 << 20
	requestWait  = 30 * time.Second
)

var releaseTag = regexp.MustCompile(`^ci-([0-9a-f]{40})-run-([0-9]{1,20})$`)

type RateLimitedError struct{ Until time.Time }

func (e *RateLimitedError) Error() string {
	return "GitHub API rate limit reached until " + e.Until.UTC().Format(time.RFC3339)
}

type Source struct {
	Client *http.Client
	Now    func() time.Time

	mu     sync.Mutex
	etag   string
	cached Release
	found  bool
	until  time.Time
}

func NewSource() *Source {
	return &Source{Client: &http.Client{Timeout: requestWait}, Now: time.Now}
}

type githubRelease struct {
	Tag    string `json:"tag_name"`
	Draft  bool   `json:"draft"`
	Assets []struct {
		Name   string `json:"name"`
		State  string `json:"state"`
		Digest string `json:"digest"`
	} `json:"assets"`
}

var ErrNoRelease = errors.New("no attested ts-orch release is published")

func (s *Source) Newest(ctx context.Context) (Release, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.Now(); now.Before(s.until) {
		return Release{}, &RateLimitedError{s.until}
	}
	headers := map[string]string{}
	if s.etag != "" {
		headers["If-None-Match"] = s.etag
	}
	response, data, err := s.get(ctx, apiBase+"/releases?per_page=30", headers, listLimit)
	if err != nil {
		return Release{}, err
	}
	if response.StatusCode == http.StatusNotModified {
		if !s.found {
			return Release{}, ErrNoRelease
		}
		return s.cached, nil
	}
	var releases []githubRelease
	if err := json.Unmarshal(data, &releases); err != nil {
		return Release{}, fmt.Errorf("GitHub releases unreadable: %w", err)
	}
	newest, found := newestRelease(releases)
	s.etag, s.cached, s.found = response.Header.Get("ETag"), newest, found
	if !found {
		return Release{}, ErrNoRelease
	}
	return newest, nil
}

func newestRelease(releases []githubRelease) (Release, bool) {
	var newest Release
	var newestRun uint64
	found := false
	for _, candidate := range releases {
		match := releaseTag.FindStringSubmatch(candidate.Tag)
		if candidate.Draft || match == nil {
			continue
		}
		run, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil || found && run <= newestRun {
			continue
		}
		release := Release{SHA: match[1], RunID: match[2], Binaries: map[string]Artifact{}}
		attested := false
		for _, asset := range candidate.Assets {
			if asset.State != "" && asset.State != "uploaded" {
				continue
			}
			switch {
			case asset.Name == BundleAsset:
				attested = true
			case strings.HasPrefix(asset.Name, AssetPrefix):
				arch := strings.TrimPrefix(asset.Name, AssetPrefix)
				if arch == "amd64" || arch == "arm64" {
					release.Binaries[arch] = Artifact{URL: AssetURL(release.SHA, release.RunID, asset.Name)}
				}
			}
		}
		if !attested || len(release.Binaries) == 0 {
			continue
		}
		release.Bundle = AssetURL(release.SHA, release.RunID, BundleAsset)
		newest, newestRun, found = release, run, true
	}
	return newest, found
}

func (s *Source) Descends(ctx context.Context, base, head string) error {
	if base == head {
		return nil
	}
	if !sha40.MatchString(base) || !sha40.MatchString(head) {
		return fmt.Errorf("%w: lineage needs two full revisions, have %q and %q", ErrRefused, base, head)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.Now(); now.Before(s.until) {
		return &RateLimitedError{s.until}
	}
	first, err := s.compare(ctx, base, head, 1)
	if err != nil {
		return err
	}
	if first.Status != "ahead" || first.AheadBy < 1 || first.Base.SHA != base || first.MergeBase.SHA != base {
		return fmt.Errorf("%w: %s does not descend from the installed %s (%s; base %s, merge base %s)", ErrRefused, head, base, first.Status, first.Base.SHA, first.MergeBase.SHA)
	}
	last := first
	if first.AheadBy > 1 {
		if last, err = s.compare(ctx, base, head, first.AheadBy); err != nil {
			return err
		}
	}
	if last.AheadBy != first.AheadBy || last.Base.SHA != base || last.MergeBase.SHA != base || len(last.Commits) != 1 || last.Commits[0].SHA != head {
		return fmt.Errorf("%w: GitHub's comparison of the installed %s does not end at %s", ErrRefused, base, head)
	}
	return nil
}

type commitRef struct {
	SHA string `json:"sha"`
}

type comparison struct {
	Status    string      `json:"status"`
	AheadBy   int         `json:"ahead_by"`
	Base      commitRef   `json:"base_commit"`
	MergeBase commitRef   `json:"merge_base_commit"`
	Commits   []commitRef `json:"commits"`
}

func (s *Source) compare(ctx context.Context, base, head string, page int) (comparison, error) {
	_, data, err := s.get(ctx, apiBase+"/compare/"+base+"..."+head+"?per_page=1&page="+strconv.Itoa(page), nil, compareLimit)
	if err != nil {
		return comparison{}, err
	}
	var result comparison
	if err := json.Unmarshal(data, &result); err != nil {
		return comparison{}, fmt.Errorf("GitHub comparison unreadable: %w", err)
	}
	return result, nil
}

func (s *Source) get(ctx context.Context, url string, headers map[string]string, limit int64) (*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := s.Client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("GitHub reply to %s exceeds %d bytes", url, limit)
	}
	if until, limited := s.rateLimit(response); limited {
		s.until = until
		return nil, nil, &RateLimitedError{until}
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified {
		return nil, nil, fmt.Errorf("GitHub %s: %s", url, response.Status)
	}
	return response, data, nil
}

func (s *Source) rateLimit(response *http.Response) (time.Time, bool) {
	now := s.Now()
	if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 &&
		(response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests) {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	if response.Header.Get("X-RateLimit-Remaining") != "0" {
		return time.Time{}, false
	}
	reset, err := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64)
	if err != nil {
		return now.Add(time.Hour), true
	}
	until := time.Unix(reset, 0)
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusNotModified {
		s.until = until
		return time.Time{}, false
	}
	return until, true
}
