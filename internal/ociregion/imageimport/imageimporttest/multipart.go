package imageimporttest

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// upload is one open multipart upload.
type upload struct {
	key      string
	metadata map[string]string
	parts    map[int][]byte
}

// Multipart reports the multipart uploads still open (neither committed
// nor aborted) and how many were aborted.
func (s *Server) Multipart() (open, aborted int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.uploads), s.aborted
}

// SetPartHook runs before every stored part; tests use it to change the
// source file mid-upload.
func (s *Server) SetPartHook(hook func(part int)) {
	s.mu.Lock()
	s.partHook = hook
	s.mu.Unlock()
}

// SetPartFailure makes every later part upload fail with status (0 clears).
func (s *Server) SetPartFailure(status int) {
	s.mu.Lock()
	s.partFailure = status
	s.mu.Unlock()
}

func (s *Server) routeMultipart(mux *http.ServeMux) {
	mux.HandleFunc("POST /n/{namespace}/b/{bucket}/u", s.createUpload)
	mux.HandleFunc("PUT /n/{namespace}/b/{bucket}/u/{object...}", s.uploadPart)
	mux.HandleFunc("POST /n/{namespace}/b/{bucket}/u/{object...}", s.commitUpload)
	mux.HandleFunc("DELETE /n/{namespace}/b/{bucket}/u/{object...}", s.abortUpload)
}

func contentMD5(data []byte) string {
	sum := md5.Sum(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (s *Server) createUpload(w http.ResponseWriter, r *http.Request) {
	var details struct {
		Object   string            `json:"object"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.UnmarshalRead(r.Body, &details); err != nil || details.Object == "" {
		refuse(w, http.StatusBadRequest, "InvalidParameter", "bad multipart upload details")
		return
	}
	// Like OCI, the body's metadata keys carry the opc-meta- prefix that a
	// PutObject header gets from the SDK; the stored object keeps the bare key.
	metadata := map[string]string{}
	for name, value := range details.Metadata {
		bare, ok := strings.CutPrefix(strings.ToLower(name), "opc-meta-")
		if !ok {
			refuse(w, http.StatusBadRequest, "InvalidMetadata", fmt.Sprintf("The metadata key %q is invalid", name))
			return
		}
		metadata[bare] = value
	}
	key := r.PathValue("namespace") + "/" + r.PathValue("bucket") + "/" + details.Object
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[key]; exists && r.Header.Get("If-None-Match") == "*" {
		refuse(w, http.StatusPreconditionFailed, "IfNoneMatchFailed", "object exists")
		return
	}
	s.uploadSeq++
	id := fmt.Sprintf("upload-%d", s.uploadSeq)
	s.uploads[id] = &upload{key: key, metadata: metadata, parts: map[int][]byte{}}
	reply(w, http.StatusOK, map[string]string{"namespace": r.PathValue("namespace"), "bucket": r.PathValue("bucket"),
		"object": details.Object, "uploadId": id, "timeCreated": s.created.Format("2006-01-02T15:04:05Z")})
}

func (s *Server) openUpload(w http.ResponseWriter, r *http.Request) *upload {
	stored, ok := s.uploads[r.URL.Query().Get("uploadId")]
	if !ok || stored.key != objectKey(r) {
		refuse(w, http.StatusNotFound, "NoSuchUpload", "upload does not exist")
		return nil
	}
	return stored
}

func (s *Server) uploadPart(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameter", err.Error())
		return
	}
	number, err := strconv.Atoi(r.URL.Query().Get("uploadPartNum"))
	if err != nil || number < 1 || number > 10000 {
		refuse(w, http.StatusBadRequest, "InvalidParameter", "bad part number")
		return
	}
	if want := r.Header.Get("Content-MD5"); want != "" && want != contentMD5(data) {
		refuse(w, http.StatusBadRequest, "InvalidContentMD5", "part MD5 mismatch")
		return
	}
	s.mu.Lock()
	if s.partFailure != 0 {
		s.mu.Unlock()
		refuse(w, s.partFailure, "NotAuthorizedOrNotFound", "part refused")
		return
	}
	hook := s.partHook
	stored := s.openUpload(w, r)
	if stored != nil {
		stored.parts[number] = data
	}
	s.mu.Unlock()
	if stored == nil {
		return
	}
	if hook != nil {
		hook(number)
	}
	w.Header().Set("ETag", fmt.Sprintf("part-%d-%s", number, contentMD5(data)))
	w.Header().Set("opc-content-md5", contentMD5(data))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) commitUpload(w http.ResponseWriter, r *http.Request) {
	var details struct {
		PartsToCommit []struct {
			PartNum int    `json:"partNum"`
			Etag    string `json:"etag"`
		} `json:"partsToCommit"`
	}
	if err := json.UnmarshalRead(r.Body, &details); err != nil || len(details.PartsToCommit) == 0 {
		refuse(w, http.StatusBadRequest, "InvalidParameter", "bad commit details")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := s.openUpload(w, r)
	if stored == nil {
		return
	}
	if _, exists := s.objects[stored.key]; exists && r.Header.Get("If-None-Match") == "*" {
		refuse(w, http.StatusPreconditionFailed, "IfNoneMatchFailed", "object exists")
		return
	}
	slices.SortFunc(details.PartsToCommit, func(a, b struct {
		PartNum int    `json:"partNum"`
		Etag    string `json:"etag"`
	}) int {
		return a.PartNum - b.PartNum
	})
	var data, md5s []byte
	for _, part := range details.PartsToCommit {
		body, ok := stored.parts[part.PartNum]
		if !ok || part.Etag != fmt.Sprintf("part-%d-%s", part.PartNum, contentMD5(body)) {
			refuse(w, http.StatusBadRequest, "InvalidPart", "part etag mismatch")
			return
		}
		data = append(data, body...)
		sum := md5.Sum(body)
		md5s = append(md5s, sum[:]...)
	}
	s.objects[stored.key] = object{data: data, metadata: stored.metadata}
	delete(s.uploads, r.URL.Query().Get("uploadId"))
	all := md5.Sum(md5s)
	w.Header().Set("opc-multipart-md5", base64.StdEncoding.EncodeToString(all[:])+"-"+strconv.Itoa(len(details.PartsToCommit)))
	w.Header().Set("ETag", "standin")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) abortUpload(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.openUpload(w, r) == nil {
		return
	}
	delete(s.uploads, r.URL.Query().Get("uploadId"))
	s.aborted++
	w.WriteHeader(http.StatusNoContent)
}
