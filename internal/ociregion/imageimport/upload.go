package imageimport

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

const (
	// uploadBufferBudget bounds the part buffers held by every upload in the
	// process together, so a multi-region import holds at most this much
	// QCOW2 data in memory however many regions upload at once. A part
	// larger than the budget is uploaded alone.
	uploadBufferBudget = 1 << 30
	// maxUploadParts is Object Storage's limit of parts per upload.
	maxUploadParts = 10000
	abortTimeout   = time.Minute
)

// uploadBuffers is shared by every upload in the process.
var uploadBuffers = semaphore.NewWeighted(uploadBufferBudget)

// ErrUploadDigestMismatch marks a QCOW2 whose bytes changed between the
// digest check and the upload. The upload is never committed.
var ErrUploadDigestMismatch = errors.New("uploaded QCOW2 bytes differ from the expected SHA-256")

// streamUpload reads the file once, sequentially, and hashes exactly the
// bytes it sends. A file of at most one part goes in one conditional PUT
// after its digest is checked; a larger file goes as a multipart upload
// that is committed only when the digest of every sent byte matches, and is
// aborted otherwise. This closes the window in which the QCOW2 could change
// between the pre-upload digest check and the upload.
func (c *sdkClient) streamUpload(ctx context.Context, request UploadRequest) error {
	if len(request.SHA256) != sha256.Size*2 {
		return errors.New("upload requires the expected SHA-256")
	}
	if request.PartSize < 1 || request.Parallelism < 1 {
		return errors.New("upload part size and parallelism must be positive")
	}
	file, err := os.Open(request.Path)
	if err != nil {
		return fmt.Errorf("open QCOW2: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat QCOW2: %w", err)
	}
	parts := &partReader{file: file, partSize: request.PartSize, expected: info.Size()}
	digest := sha256.New()
	first, release, err := parts.next(ctx)
	if err != nil {
		return err
	}
	if int64(len(first)) < request.PartSize {
		defer release()
		digest.Write(first)
		if err := matches(digest, request.SHA256); err != nil {
			return err
		}
		sum := md5.Sum(first)
		_, err := c.objects.PutObject(ctx, objectstorage.PutObjectRequest{NamespaceName: new(request.Namespace),
			BucketName: new(request.Bucket), ObjectName: new(request.Object), ContentLength: new(int64(len(first))),
			PutObjectBody: io.NopCloser(bytes.NewReader(first)), IfNoneMatch: new("*"), OpcMeta: request.Metadata,
			ContentMD5: new(base64.StdEncoding.EncodeToString(sum[:]))})
		if err != nil {
			return fmt.Errorf("upload OCI object: %w", err)
		}
		return nil
	}
	return c.multipartUpload(ctx, request, parts, digest, first, release)
}

// partReader reads the QCOW2 sequentially in parts. Buffers are sized by
// the bytes the file was stated to have left (plus one, so growth is still
// read and fails the digest), never by the part size alone: a small file
// with a huge configured part size does not allocate the part size.
type partReader struct {
	file     io.Reader
	partSize int64
	expected int64
	offset   int64
}

// next reads the next part after reserving its buffer from the process
// budget. release returns the reservation.
func (p *partReader) next(ctx context.Context) ([]byte, func(), error) {
	size := min(p.partSize, max(p.expected-p.offset, 0)+1)
	weight := min(size, uploadBufferBudget)
	if err := uploadBuffers.Acquire(ctx, weight); err != nil {
		return nil, nil, err
	}
	release := sync.OnceFunc(func() { uploadBuffers.Release(weight) })
	buffer := make([]byte, size)
	n, err := io.ReadFull(p.file, buffer)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		release()
		return nil, nil, fmt.Errorf("read QCOW2: %w", err)
	}
	p.offset += int64(n)
	return buffer[:n], release, nil
}

func matches(digest hash.Hash, want string) error {
	if hex.EncodeToString(digest.Sum(nil)) != want {
		return ErrUploadDigestMismatch
	}
	return nil
}

func (c *sdkClient) multipartUpload(ctx context.Context, request UploadRequest, parts *partReader, digest hash.Hash,
	first []byte, release func(),
) (err error) {
	// Unlike PutObject's OpcMeta header, the multipart body takes the
	// opc-meta- prefix in each key; OCI refuses a bare key.
	metadata := make(map[string]string, len(request.Metadata))
	for name, value := range request.Metadata {
		metadata["opc-meta-"+name] = value
	}
	created, err := c.objects.CreateMultipartUpload(ctx, objectstorage.CreateMultipartUploadRequest{
		NamespaceName: new(request.Namespace), BucketName: new(request.Bucket), IfNoneMatch: new("*"),
		CreateMultipartUploadDetails: objectstorage.CreateMultipartUploadDetails{Object: new(request.Object),
			Metadata: metadata}})
	if err != nil {
		release()
		return fmt.Errorf("create OCI multipart upload: %w", err)
	}
	if created.UploadId == nil || *created.UploadId == "" {
		release()
		return errors.New("OCI multipart upload has no upload id")
	}
	uploadID := *created.UploadId
	committed := false
	defer func() {
		if committed {
			return
		}
		// Never leave the uncommitted parts behind, even when ctx ended.
		abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
		defer cancel()
		if _, abortErr := c.objects.AbortMultipartUpload(abortCtx, objectstorage.AbortMultipartUploadRequest{
			NamespaceName: new(request.Namespace), BucketName: new(request.Bucket), ObjectName: new(request.Object),
			UploadId: new(uploadID)}); abortErr != nil {
			err = errors.Join(err, fmt.Errorf("abort OCI multipart upload %s: %w", uploadID, abortErr))
		}
	}()

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(request.Parallelism)
	// Keep cancellation out of common.Retry's unsynchronized result path
	// (oci-go-sdk v65.126.0/1), but restore it before rate limiting and HTTP
	// dispatch so stalled writes and response headers still get canceled.
	objects := c.objects
	intercept := objects.Interceptor
	objects.Interceptor = func(request *http.Request) error {
		*request = *request.WithContext(groupCtx)
		if err := groupCtx.Err(); err != nil {
			return err
		}
		if intercept != nil {
			return intercept(request)
		}
		return nil
	}
	retry := c.uploadRetry
	retry.ShouldRetryOperation = func(response common.OCIOperationResponse) bool {
		if groupCtx.Err() != nil || !c.uploadRetry.ShouldRetryOperation(response) {
			return false
		}
		// Wait here instead of common.Retry's unconditional backoff timer.
		timer := time.NewTimer(c.uploadRetry.NextDuration(response))
		defer timer.Stop()
		select {
		case <-groupCtx.Done():
			return false
		case <-timer.C:
			return groupCtx.Err() == nil
		}
	}
	retry.NextDuration = func(common.OCIOperationResponse) time.Duration { return 0 }
	var mu sync.Mutex
	etags := map[int]string{}
	var md5s [][]byte
	part, buffer := 0, first
	for len(buffer) > 0 {
		part++
		if part > maxUploadParts {
			release()
			return errors.Join(group.Wait(),
				fmt.Errorf("QCOW2 needs more than %d parts; raise the part size", maxUploadParts))
		}
		digest.Write(buffer)
		sum := md5.Sum(buffer)
		md5s = append(md5s, sum[:])
		number, body, done := part, buffer, release
		group.Go(func() error {
			defer done()
			response, err := objects.UploadPart(context.WithoutCancel(groupCtx), objectstorage.UploadPartRequest{
				NamespaceName: new(request.Namespace), BucketName: new(request.Bucket), ObjectName: new(request.Object),
				UploadId: new(uploadID), UploadPartNum: new(number), ContentLength: new(int64(len(body))),
				UploadPartBody: io.NopCloser(bytes.NewReader(body)),
				ContentMD5:     new(base64.StdEncoding.EncodeToString(sum[:])),
				// Replaying a part of the same bytes and number is idempotent.
				RequestMetadata: common.RequestMetadata{RetryPolicy: &retry}})
			if err != nil {
				if cancelErr := groupCtx.Err(); cancelErr != nil {
					err = cancelErr
				}
				return fmt.Errorf("upload OCI part %d: %w", number, err)
			}
			if response.ETag == nil || *response.ETag == "" {
				return fmt.Errorf("OCI part %d has no ETag", number)
			}
			mu.Lock()
			etags[number] = *response.ETag
			mu.Unlock()
			return nil
		})
		if int64(len(buffer)) < request.PartSize {
			break
		}
		if buffer, release, err = parts.next(groupCtx); err != nil {
			// A failed part cancels groupCtx; report its cause, not the
			// cancellation it caused here.
			if workerErr := group.Wait(); workerErr != nil {
				return workerErr
			}
			return err
		}
		if len(buffer) == 0 {
			release()
		}
	}
	if err := group.Wait(); err != nil {
		return err
	}
	// Every byte sent has been hashed in order; commit only an exact match.
	if err := matches(digest, request.SHA256); err != nil {
		return err
	}
	commit := make([]objectstorage.CommitMultipartUploadPartDetails, 0, part)
	for number := 1; number <= part; number++ {
		commit = append(commit, objectstorage.CommitMultipartUploadPartDetails{PartNum: new(number), Etag: new(etags[number])})
	}
	response, err := c.objects.CommitMultipartUpload(ctx, objectstorage.CommitMultipartUploadRequest{
		NamespaceName: new(request.Namespace), BucketName: new(request.Bucket), ObjectName: new(request.Object),
		UploadId: new(uploadID), IfNoneMatch: new("*"),
		CommitMultipartUploadDetails: objectstorage.CommitMultipartUploadDetails{PartsToCommit: commit}})
	if err != nil {
		return fmt.Errorf("commit OCI multipart upload: %w", err)
	}
	committed = true
	if want := multipartMD5(md5s); response.OpcMultipartMd5 == nil || *response.OpcMultipartMd5 != want {
		// The stored object is not the verified bytes; remove exactly that
		// object version so its sha256 metadata can never vouch for it.
		mismatch := fmt.Errorf("committed OCI object multipart MD5 differs from the bytes sent (want %s)", want)
		if response.ETag == nil || *response.ETag == "" {
			// Without the commit's ETag a delete could remove a different
			// object written since; leave it for an operator instead.
			return fmt.Errorf("%w; the commit returned no ETag, so the object was not deleted", mismatch)
		}
		deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
		defer cancel()
		if _, deleteErr := c.objects.DeleteObject(deleteCtx, objectstorage.DeleteObjectRequest{
			NamespaceName: new(request.Namespace), BucketName: new(request.Bucket), ObjectName: new(request.Object),
			IfMatch: response.ETag}); deleteErr != nil {
			return errors.Join(mismatch, fmt.Errorf("delete mismatched OCI object: %w", deleteErr))
		}
		return mismatch
	}
	return nil
}

// multipartMD5 is Object Storage's checksum of a multipart object: the MD5
// of the concatenated part MD5s, base64, with the part count.
func multipartMD5(parts [][]byte) string {
	all := md5.New()
	for _, sum := range parts {
		all.Write(sum)
	}
	return base64.StdEncoding.EncodeToString(all.Sum(nil)) + "-" + strconv.Itoa(len(parts))
}
