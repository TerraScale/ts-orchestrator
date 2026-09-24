package host

import (
	"context"
	"errors"
	"os"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/nats-io/nats.go/jetstream"
)

var errArtifactPreparing = errors.New("artifact preparing")

// readArtifactChunk serves a verified content-addressed spool. One controller
// downloads at most one object at a time and retains at most one 512 MiB file.
func (c *Controller) readArtifactChunk(ctx context.Context, digest string, offset int64, length int) ([]byte, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cacheClosed {
		return nil, 0, errors.New("artifact cache is closed")
	}
	if c.cacheDigest != digest || c.cacheFile == nil {
		if !c.cacheDownloading && !time.Now().Before(c.cacheRetryAfter) {
			c.cacheDownloading = true
			go c.downloadArtifact(digest)
		}
		return nil, 0, errArtifactPreparing
	}
	if offset < 0 || offset >= c.cacheSize {
		return nil, 0, errors.New("artifact offset is outside object")
	}
	count := min(int64(length), c.cacheSize-offset)
	data := make([]byte, count)
	if _, err := c.cacheFile.ReadAt(data, offset); err != nil {
		return nil, 0, err
	}
	return data, c.cacheSize, nil
}

func (c *Controller) downloadArtifact(digest string) {
	ctx, cancel := context.WithTimeout(c.cacheContext, 2*time.Minute)
	defer cancel()
	var downloaded *os.File
	var size int64
	var fetchErr error
	defer func() {
		c.cacheMu.Lock()
		defer c.cacheMu.Unlock()
		c.cacheDownloading = false
		if c.cacheClosed || fetchErr != nil {
			if downloaded != nil {
				_ = downloaded.Close()
			}
			if fetchErr != nil {
				c.cacheRetryAfter = time.Now().Add(3 * time.Second)
			}
			return
		}
		if c.cacheFile != nil {
			_ = c.cacheFile.Close()
		}
		c.cacheFile = downloaded
		c.cacheDigest = digest
		c.cacheSize = size
	}()
	info, err := c.artifacts.GetInfo(ctx, "sha256-"+digest)
	if err != nil {
		fetchErr = err
		return
	}
	if info == nil || info.Deleted || info.Opts != nil && info.Opts.Link != nil || info.Size == 0 || info.Size > maxArtifactBytes {
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
		digest, int64(info.Size), maxArtifactBytes, file); err != nil {
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
	if c.cacheFile != nil {
		_ = c.cacheFile.Close()
		c.cacheFile = nil
	}
}
