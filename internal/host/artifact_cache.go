package host

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/nats-io/nats.go/jetstream"
)

var errArtifactPreparing = errors.New("artifact preparing")

type artifactCache struct {
	file        *os.File
	digest      string
	size        int64
	downloading bool
	retryAfter  time.Time
}

// Workloads and NetBird each retain one bounded verified spool, so their
// interleaved chunk requests cannot evict each other's in-flight downloads.
func (c *Controller) readArtifactChunk(ctx context.Context, digest string, offset int64, length int) ([]byte, int64, error) {
	return c.readCachedArtifact(ctx, &c.workloadCache, maxArtifactBytes, digest, offset, length)
}

func (c *Controller) readCachedArtifact(ctx context.Context, cache *artifactCache, maxBytes int64, digest string, offset int64, length int) ([]byte, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cacheClosed {
		return nil, 0, errors.New("artifact cache is closed")
	}
	if cache.digest != digest || cache.file == nil {
		if !cache.downloading && !time.Now().Before(cache.retryAfter) {
			cache.downloading = true
			go c.downloadArtifact(cache, maxBytes, digest)
		}
		return nil, 0, errArtifactPreparing
	}
	if offset < 0 || offset >= cache.size {
		return nil, 0, errors.New("artifact offset is outside object")
	}
	count := min(int64(length), cache.size-offset)
	data := make([]byte, count)
	if _, err := cache.file.ReadAt(data, offset); err != nil {
		return nil, 0, err
	}
	return data, cache.size, nil
}

func (c *Controller) downloadArtifact(cache *artifactCache, maxBytes int64, digest string) {
	ctx, cancel := context.WithTimeout(c.cacheContext, 2*time.Minute)
	defer cancel()
	var downloaded *os.File
	var size int64
	var fetchErr error
	defer func() {
		c.cacheMu.Lock()
		defer c.cacheMu.Unlock()
		cache.downloading = false
		if c.cacheClosed || fetchErr != nil {
			if downloaded != nil {
				_ = downloaded.Close()
			}
			if fetchErr != nil {
				cache.retryAfter = time.Now().Add(3 * time.Second)
			}
			return
		}
		if cache.file != nil {
			_ = cache.file.Close()
		}
		cache.file = downloaded
		cache.digest = digest
		cache.size = size
	}()
	info, err := c.artifacts.GetInfo(ctx, "sha256-"+digest)
	if err != nil {
		fetchErr = err
		return
	}
	if info == nil || info.Deleted || info.Opts != nil && info.Opts.Link != nil || info.Size == 0 || info.Size > uint64(maxBytes) {
		fetchErr = errors.New("artifact metadata is invalid")
		return
	}
	js, err := jetstream.New(c.conn)
	if err != nil {
		fetchErr = err
		return
	}
	file, err := os.CreateTemp("", "ts-host-artifact-*")
	if err != nil {
		fetchErr = err
		return
	}
	_ = os.Remove(file.Name())
	downloaded = file
	if err := artifact.ReadVerified(ctx, js, c.artifacts, info.Bucket, "sha256-"+digest,
		digest, int64(info.Size), maxBytes, file); err != nil {
		fetchErr = err
		return
	}
	if err := file.Sync(); err != nil {
		fetchErr = err
		return
	}
	size = int64(info.Size)
}

func (c *Controller) closeCache() {
	c.cacheCancel()
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cacheClosed = true
	for _, cache := range []*artifactCache{&c.workloadCache, &c.netbirdCache} {
		if cache.file != nil {
			_ = cache.file.Close()
			cache.file = nil
		}
	}
}
