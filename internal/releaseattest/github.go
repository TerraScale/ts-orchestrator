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

	mu      sync.Mutex
	etag    string
	cached  Release
	found   bool
	until   time.Time
	lineage lineage
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

var (
	ErrNoRelease = errors.New("no attested ts-orch release is published")
	ErrOlder     = errors.New("release is older than the installed one")
)

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
	if s.lineage.base == base && s.lineage.head == head {
		return s.lineage.verdict
	}
	if now := s.Now(); now.Before(s.until) {
		return &RateLimitedError{s.until}
	}
	found, err := s.compare(ctx, head, base)
	if err != nil {
		return err
	}
	s.lineage = lineage{base: base, head: head, verdict: found.descends(base, head)}
	return s.lineage.verdict
}

type lineage struct {
	base    string
	head    string
	verdict error
}

type commitRef struct {
	SHA string `json:"sha"`
}

type comparison struct {
	Status    string
	AheadBy   int
	BehindBy  int
	Base      commitRef
	MergeBase commitRef
}

func (c comparison) descends(base, head string) error {
	switch {
	case c.Base.SHA != head:
		return fmt.Errorf("%w: GitHub resolved %s to %s", ErrRefused, head, c.Base.SHA)
	case c.Status == "behind" && c.AheadBy == 0 && c.BehindBy > 0 && c.MergeBase.SHA == base:
		return nil
	case c.Status == "ahead" && c.BehindBy == 0 && c.AheadBy > 0 && c.MergeBase.SHA == head:
		return fmt.Errorf("%w: the installed %s already descends from %s", ErrOlder, base, head)
	}
	return fmt.Errorf("%w: %s does not descend from the installed %s (%s; merge base %s)", ErrRefused, head, base, c.Status, c.MergeBase.SHA)
}

func (s *Source) compare(ctx context.Context, head, base string) (comparison, error) {
	url := apiBase + "/compare/" + head + "..." + base + "?per_page=1"
	response, err := s.open(ctx, url, nil)
	if err != nil {
		return comparison{}, err
	}
	defer response.Body.Close()
	var found comparison
	fields := map[string]any{"status": &found.Status, "ahead_by": &found.AheadBy, "behind_by": &found.BehindBy,
		"base_commit": &found.Base, "merge_base_commit": &found.MergeBase}
	decoder := json.NewDecoder(io.LimitReader(response.Body, compareLimit))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return comparison{}, fmt.Errorf("GitHub comparison %s is not an object", url)
	}
	for len(fields) > 0 {
		if !decoder.More() {
			return comparison{}, fmt.Errorf("GitHub comparison %s lacks %d of its lineage fields", url, len(fields))
		}
		token, err := decoder.Token()
		if err != nil {
			return comparison{}, fmt.Errorf("GitHub comparison %s unreadable in its first %d bytes: %w", url, compareLimit, err)
		}
		key, _ := token.(string)
		target, wanted := fields[key]
		if !wanted {
			target = new(json.RawMessage)
		}
		if err := decoder.Decode(target); err != nil {
			return comparison{}, fmt.Errorf("GitHub comparison %s unreadable in its first %d bytes: %w", url, compareLimit, err)
		}
		delete(fields, key)
	}
	return found, nil
}

func (s *Source) open(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}
	if until, limited := s.rateLimit(response); limited {
		response.Body.Close()
		s.until = until
		return nil, &RateLimitedError{until}
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified {
		response.Body.Close()
		return nil, fmt.Errorf("GitHub %s: %s", url, response.Status)
	}
	return response, nil
}

func (s *Source) get(ctx context.Context, url string, headers map[string]string, limit int64) (*http.Response, []byte, error) {
	response, err := s.open(ctx, url, headers)
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
