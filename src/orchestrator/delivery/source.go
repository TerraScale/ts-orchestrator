package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	MaximumSourceFileBytes    = 1 << 20
	MaximumSourceArchiveBytes = 256 << 20
	MaximumChangedPaths       = 4096
	CIDescriptorPath          = ".terrascale/ci-v2.json"
)

type SourceConfig struct {
	Server     *url.URL
	Repository string
	TokenFile  string
}

func ResolveSourceConfig(server, repository, tokenFile string) (SourceConfig, error) {
	if strings.TrimSpace(server) == "" && strings.TrimSpace(tokenFile) == "" {
		return SourceConfig{}, nil
	}
	if strings.TrimSpace(server) == "" || strings.TrimSpace(tokenFile) == "" || !ValidRepository(repository) {
		return SourceConfig{}, errors.New("source configuration requires server, repository, and token file")
	}
	u, e := url.Parse(server)
	if e != nil || u.Scheme != "https" && u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return SourceConfig{}, errors.New("source server URL is invalid")
	}
	if !strings.HasSuffix(u.Path, "/") {
		return SourceConfig{}, errors.New("source server URL must end with /")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return SourceConfig{}, errors.New("plaintext source server must be loopback")
	}
	p, e := privateFile(tokenFile, 20, 4096)
	if e != nil {
		return SourceConfig{}, e
	}
	return SourceConfig{Server: u, Repository: repository, TokenFile: p}, nil
}
func (c SourceConfig) ForRepository(repo string) (SourceConfig, error) {
	if !ValidRepository(repo) {
		return SourceConfig{}, errors.New("invalid repository")
	}
	return SourceConfig{Server: c.Server, Repository: repo, TokenFile: c.TokenFile}, nil
}
func (c SourceConfig) token() (string, error) {
	b, e := readSecret(c.TokenFile, 20, 4096)
	if e != nil {
		return "", e
	}
	defer clear(b)
	s := string(b)
	if strings.TrimSpace(s) != s || len(s) < 20 || len(s) > 4096 || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return "", errors.New("Forgejo API token is invalid")
	}
	return s, nil
}

type ResolvedRevision struct {
	Repository, Commit, Tree string
	SignatureVerified        bool
}
type BranchObservation struct {
	Branch    string
	Protected bool
	Revision  ResolvedRevision
}
type SourceFile struct {
	Repository, Commit, Path, Blob, ContentSHA256 string
	Content                                       []byte
}
type SourceArchive struct {
	Revision      ResolvedRevision
	ContentSHA256 string
	Content       []byte
}

var ErrSourceNotFound = errors.New("Forgejo source revision was not found")

type SourceNotFoundError struct{}

func (SourceNotFoundError) Error() string { return ErrSourceNotFound.Error() }
func (SourceNotFoundError) Is(target error) bool {
	if target == ErrSourceNotFound {
		return true
	}
	switch target.(type) {
	case SourceNotFoundError, *SourceNotFoundError:
		return true
	default:
		return false
	}
}

type SourceClient struct {
	config SourceConfig
	http   *http.Client
	mutex  sync.RWMutex
	closed bool
	ctx    context.Context
	cancel context.CancelFunc
}

func NewSourceClient(config SourceConfig, client *http.Client) (*SourceClient, error) {
	if config.Server == nil || !ValidRepository(config.Repository) {
		return nil, errors.New("invalid source configuration")
	}
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: nil, DisableCompression: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 0}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &SourceClient{config: config, http: client, ctx: ctx, cancel: cancel}, nil
}
func (c *SourceClient) Close() error {
	if c == nil {
		return errors.New("source client is unavailable")
	}
	c.mutex.Lock()
	if !c.closed {
		c.closed = true
		if c.cancel != nil {
			c.cancel()
		}
	}
	c.mutex.Unlock()
	return nil
}

// requestContext validates the caller context and binds it to the client's
// lifecycle. Closing the client therefore cancels in-flight HTTP requests;
// callers cannot accidentally pass nil to the context-aware net/http APIs.
func (c *SourceClient) requestContext(ctx context.Context) (context.Context, func(), error) {
	if c == nil {
		return nil, nil, errors.New("source client is unavailable")
	}
	if ctx == nil {
		return nil, nil, errors.New("source context must not be nil")
	}
	c.mutex.RLock()
	closed := c.closed
	clientContext := c.ctx
	c.mutex.RUnlock()
	if closed {
		return nil, nil, errors.New("source client is closed")
	}
	if clientContext == nil {
		clientContext = context.Background()
	}
	effective, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		select {
		case <-clientContext.Done():
			cancel()
		case <-done:
		}
	}()
	stop := func() {
		close(done)
		cancel()
	}
	return effective, stop, nil
}

func (c *SourceClient) checkContext(ctx context.Context) error {
	if c == nil {
		return errors.New("source client is unavailable")
	}
	if ctx == nil {
		return errors.New("source context must not be nil")
	}
	c.mutex.RLock()
	closed := c.closed
	c.mutex.RUnlock()
	if closed {
		return errors.New("source client is closed")
	}
	if c.http == nil || c.config.Server == nil || !ValidRepository(c.config.Repository) {
		return errors.New("source client is not configured")
	}
	return nil
}
func (c *SourceClient) Resolve(ctx context.Context, commit string) (ResolvedRevision, error) {
	if err := c.checkContext(ctx); err != nil {
		return ResolvedRevision{}, err
	}
	if !objectID(commit) || allZero(commit) {
		return ResolvedRevision{}, errors.New("invalid commit")
	}
	owner, repo := splitRepo(c.config.Repository)
	path := fmt.Sprintf("api/v1/repos/%s/%s/git/commits/%s?stat=false&verification=true&files=false", url.PathEscape(owner), url.PathEscape(repo), strings.ToLower(commit))
	var root map[string]json.RawMessage
	if e := c.getJSON(ctx, path, 64<<10, &root); e != nil {
		return ResolvedRevision{}, e
	}
	observed, ok := stringField(root, "sha")
	if !ok || !strings.EqualFold(observed, commit) {
		return ResolvedRevision{}, errors.New("Forgejo commit identity changed")
	}
	var co, to, v map[string]json.RawMessage
	if !objectField(root, "commit", &co) || !objectField(co, "tree", &to) {
		return ResolvedRevision{}, errors.New("Forgejo commit response is invalid")
	}
	tree, ok := stringField(to, "sha")
	if !ok || !objectID(tree) || allZero(tree) {
		return ResolvedRevision{}, errors.New("Forgejo tree identity is invalid")
	}
	verified := false
	if objectField(co, "verification", &v) {
		verified, _ = boolField(v, "verified")
	}
	return ResolvedRevision{Repository: c.config.Repository, Commit: strings.ToLower(observed), Tree: strings.ToLower(tree), SignatureVerified: verified}, nil
}
func (c *SourceClient) PollBranch(ctx context.Context, branch string) (BranchObservation, error) {
	if err := c.checkContext(ctx); err != nil {
		return BranchObservation{}, err
	}
	if branch != "develop" && branch != "main" {
		return BranchObservation{}, errors.New("branch polling is restricted")
	}
	owner, repo := splitRepo(c.config.Repository)
	var root map[string]json.RawMessage
	e := c.getJSON(ctx, fmt.Sprintf("api/v1/repos/%s/%s/branches/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(branch)), 64<<10, &root)
	if e != nil {
		return BranchObservation{}, e
	}
	name, ok := stringField(root, "name")
	if !ok || name != branch {
		return BranchObservation{}, errors.New("Forgejo branch identity changed")
	}
	protected, pok := boolField(root, "protected")
	var co map[string]json.RawMessage
	if !pok || !objectField(root, "commit", &co) {
		return BranchObservation{}, errors.New("Forgejo branch response is invalid")
	}
	commit, cok := stringField(co, "id")
	if !cok || !objectID(commit) || allZero(commit) {
		return BranchObservation{}, errors.New("Forgejo branch commit is invalid")
	}
	rev, e := c.Resolve(ctx, commit)
	if e != nil {
		return BranchObservation{}, e
	}
	return BranchObservation{Branch: branch, Protected: protected, Revision: rev}, nil
}
func (c *SourceClient) ReadChangedPaths(ctx context.Context, event *WebhookEnvelope) ([]string, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	if event == nil || event.Repository != c.config.Repository || !objectID(event.BaseRevision) || !objectID(event.Revision) || allZero(event.Revision) || event.IsDeletion {
		return nil, errors.New("event does not identify comparable revisions")
	}
	if allZero(event.BaseRevision) {
		return []string{CIDescriptorPath}, nil
	}
	owner, repo := splitRepo(c.config.Repository)
	rangePath := url.PathEscape(strings.ToLower(event.BaseRevision) + "..." + strings.ToLower(event.Revision))
	var root map[string]json.RawMessage
	if e := c.getJSON(ctx, fmt.Sprintf("api/v1/repos/%s/%s/compare/%s", url.PathEscape(owner), url.PathEscape(repo), rangePath), 8<<20, &root); e != nil {
		return nil, e
	}
	var files []json.RawMessage
	if b, ok := root["files"]; !ok || json.Unmarshal(b, &files) != nil || len(files) < 1 || len(files) > MaximumChangedPaths {
		return nil, errors.New("Forgejo comparison exceeds path bound")
	}
	seen := map[string]struct{}{}
	paths := map[string]struct{}{}
	for _, b := range files {
		var f map[string]json.RawMessage
		if json.Unmarshal(b, &f) != nil {
			return nil, errors.New("invalid changed path")
		}
		name, ok := stringField(f, "filename")
		status, sok := stringField(f, "status")
		if !ok || !sok || !safePath(name) || !validChangeStatus(status) {
			return nil, errors.New("invalid changed path")
		}
		if _, ok := seen[name]; ok {
			return nil, errors.New("ambiguous changed path")
		}
		seen[name] = struct{}{}
		paths[name] = struct{}{}
		if status == "renamed" || status == "copied" {
			paths[CIDescriptorPath] = struct{}{}
		}
	}
	out := make([]string, 0, len(paths))
	for p := range paths {
		out = append(out, p)
	}
	sortStrings(out)
	return out, nil
}
func (c *SourceClient) ReadFile(ctx context.Context, commit, path string, maximum int) (SourceFile, error) {
	if err := c.checkContext(ctx); err != nil {
		return SourceFile{}, err
	}
	if !objectID(commit) || allZero(commit) || !safePath(path) || maximum < 1 || maximum > MaximumSourceFileBytes {
		return SourceFile{}, errors.New("invalid source file request")
	}
	owner, repo := splitRepo(c.config.Repository)
	encoded := pathEscapeSegments(path)
	var root map[string]json.RawMessage
	if e := c.getJSON(ctx, fmt.Sprintf("api/v1/repos/%s/%s/contents/%s?ref=%s", url.PathEscape(owner), url.PathEscape(repo), encoded, strings.ToLower(commit)), maximum*4/3+64<<10, &root); e != nil {
		return SourceFile{}, e
	}
	name := path[strings.LastIndex(path, "/")+1:]
	typ, _ := stringField(root, "type")
	observedName, _ := stringField(root, "name")
	observedPath, _ := stringField(root, "path")
	blob, _ := stringField(root, "sha")
	enc, _ := stringField(root, "encoding")
	encodedContent, ok := stringField(root, "content")
	var size int64
	if b, yes := root["size"]; yes {
		size, _ = json.Number(string(b)).Int64()
	}
	if typ != "file" || observedName != name || observedPath != path || !objectID(blob) || allZero(blob) || enc != "base64" || size < 0 || size > int64(maximum) || !ok {
		return SourceFile{}, errors.New("Forgejo file identity is invalid")
	}
	content, e := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encodedContent), ""))
	if e != nil || len(content) != int(size) || len(content) > maximum {
		return SourceFile{}, errors.New("Forgejo file content is invalid")
	}
	sum := sha256.Sum256(content)
	return SourceFile{Repository: c.config.Repository, Commit: strings.ToLower(commit), Path: path, Blob: strings.ToLower(blob), ContentSHA256: fmt.Sprintf("%x", sum), Content: content}, nil
}
func (c *SourceClient) ReadArchive(ctx context.Context, revision ResolvedRevision) (SourceArchive, error) {
	effectiveContext, stop, err := c.requestContext(ctx)
	if err != nil {
		return SourceArchive{}, err
	}
	defer stop()
	if revision.Repository != c.config.Repository || !objectID(revision.Commit) || allZero(revision.Commit) || !objectID(revision.Tree) || allZero(revision.Tree) {
		return SourceArchive{}, errors.New("invalid source revision")
	}
	owner, repo := splitRepo(c.config.Repository)
	path := fmt.Sprintf("api/v1/repos/%s/%s/archive/%s.tar.gz", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(strings.ToLower(revision.Commit)))
	token, e := c.config.token()
	if e != nil {
		return SourceArchive{}, e
	}
	request, e := http.NewRequestWithContext(effectiveContext, http.MethodGet, sourceEndpoint(c.config.Server, path), nil)
	if e != nil {
		return SourceArchive{}, e
	}
	request.Header.Set("Authorization", "token "+token)
	request.Header.Set("Accept", "application/gzip, application/octet-stream")
	with, cancel := context.WithTimeout(request.Context(), 2*time.Minute)
	defer cancel()
	request = request.WithContext(with)
	response, e := c.http.Do(request)
	if e != nil {
		return SourceArchive{}, e
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return SourceArchive{}, SourceNotFoundError{}
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return SourceArchive{}, errors.New("Forgejo credentials were denied")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return SourceArchive{}, fmt.Errorf("Forgejo archive retrieval: %s", response.Status)
	}
	ct := response.Header.Get("Content-Type")
	if !strings.EqualFold(strings.Split(ct, ";")[0], "application/gzip") && !strings.EqualFold(strings.Split(ct, ";")[0], "application/octet-stream") || response.Header.Get("Content-Encoding") != "" {
		return SourceArchive{}, errors.New("archive is not an unencoded gzip")
	}
	// ContentLength is optional for a streamed/chunked response. The bounded
	// reader below remains the authority in that case; reject only a known
	// empty or oversized response.
	if response.ContentLength == 0 || response.ContentLength > MaximumSourceArchiveBytes {
		return SourceArchive{}, errors.New("archive exceeds bound")
	}
	content, e := readBounded(response.Body, MaximumSourceArchiveBytes)
	if e != nil || response.ContentLength > 0 && len(content) != int(response.ContentLength) || len(content) < 3 || content[0] != 0x1f || content[1] != 0x8b || content[2] != 0x08 {
		return SourceArchive{}, errors.New("archive is invalid")
	}
	sum := sha256.Sum256(content)
	return SourceArchive{Revision: revision, ContentSHA256: fmt.Sprintf("%x", sum), Content: content}, nil
}
func (c *SourceClient) getJSON(ctx context.Context, path string, maximum int, out *map[string]json.RawMessage) error {
	effectiveContext, stop, err := c.requestContext(ctx)
	if err != nil {
		return err
	}
	defer stop()
	token, e := c.config.token()
	if e != nil {
		return e
	}
	effectiveContext, cancel := context.WithTimeout(effectiveContext, 10*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(effectiveContext, http.MethodGet, sourceEndpoint(c.config.Server, path), nil)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	resp, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return SourceNotFoundError{}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return errors.New("Forgejo credentials were denied")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Forgejo request failed: %s", resp.Status)
	}
	if !strings.EqualFold(strings.Split(resp.Header.Get("Content-Type"), ";")[0], "application/json") {
		return errors.New("Forgejo response is not JSON")
	}
	b, e := readBounded(resp.Body, maximum)
	if e != nil {
		return e
	}
	if duplicateJSONProperties(b) {
		return errors.New("Forgejo response has ambiguous fields")
	}
	if e = json.Unmarshal(b, out); e != nil {
		return errors.New("Forgejo response is invalid JSON")
	}
	return nil
}
func readBounded(r io.Reader, max int) ([]byte, error) {
	b := make([]byte, 0, minInt(max, 64<<10))
	buf := make([]byte, 16<<10)
	for {
		n, e := r.Read(buf)
		if n > 0 {
			if len(b)+n > max {
				return nil, errors.New("response exceeds bound")
			}
			b = append(b, buf[:n]...)
		}
		if e == io.EOF {
			return b, nil
		}
		if e != nil {
			return nil, e
		}
	}
}
func objectID(s string) bool              { return (len(s) == 40 || len(s) == 64) && allHex(s) }
func splitRepo(s string) (string, string) { i := strings.IndexByte(s, '/'); return s[:i], s[i+1:] }
func safePath(s string) bool {
	if len(s) == 0 || len(s) > 512 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-/", c)) {
			return false
		}
	}
	return true
}
func validChangeStatus(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c == '-') {
			return false
		}
	}
	return true
}
func pathEscapeSegments(s string) string {
	p := strings.Split(s, "/")
	for i := range p {
		p[i] = url.PathEscape(p[i])
	}
	return strings.Join(p, "/")
}
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
func boolField(m map[string]json.RawMessage, key string) (bool, bool) {
	b, ok := m[key]
	if !ok {
		return false, false
	}
	var v bool
	e := json.Unmarshal(b, &v)
	return v, e == nil
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func sourceEndpoint(base *url.URL, path string) string {
	rel, err := url.Parse(path)
	if err != nil {
		return base.ResolveReference(&url.URL{Path: path}).String()
	}
	return base.ResolveReference(rel).String()
}
