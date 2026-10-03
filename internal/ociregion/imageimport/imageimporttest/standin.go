// Package imageimporttest is a local OCI stand-in for the image importer.
//
// It serves the exact REST surface the in-binary SDK client of
// imageimport uses (Object Storage HEAD/PUT, Compute CreateImage and image
// reads, the core work request, image capability schemas and shape
// compatibility) over plain HTTP on the loopback interface, so tests run the
// real SDK client, request signing, upload manager, work request polling and
// resume logic without cloud access.
//
// It is test support only: no production package imports it, and the only
// way to aim a client at it is the Go-level endpoint argument of
// imageimport.NewClient, which no flag or environment variable reaches.
package imageimporttest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
)

// WorkRequestPolls is how many times a new import work request reports
// IN_PROGRESS before it succeeds, so every import exercises polling.
const WorkRequestPolls = 2

// BillableSizeGB is the billable size every imported image reports.
const BillableSizeGB = 3

type image struct {
	ID            string `json:"id"`
	CompartmentID string `json:"compartmentId"`
	DisplayName   string `json:"displayName"`
	State         string `json:"lifecycleState"`
	Billable      int64  `json:"billableSizeInGBs"`
	TimeCreated   string `json:"timeCreated"`
}

type object struct {
	data     []byte
	metadata map[string]string
}

type schema struct {
	ID            string         `json:"id"`
	CompartmentID string         `json:"compartmentId"`
	ImageID       string         `json:"imageId"`
	DisplayName   string         `json:"displayName"`
	Version       string         `json:"computeGlobalImageCapabilitySchemaVersionName"`
	SchemaData    jsontext.Value `json:"schemaData"`
	TimeCreated   string         `json:"timeCreated"`
}

type shape struct {
	ImageID string          `json:"imageId"`
	Shape   string          `json:"shape"`
	OCPU    *jsontext.Value `json:"ocpuConstraints,omitempty"`
	Memory  *jsontext.Value `json:"memoryConstraints,omitempty"`
}

// Server is one stand-in OCI region. Its state outlives individual clients,
// so a test can run several promotions (and resumes) against one region.
type Server struct {
	URL string

	imageID string
	created time.Time

	mu       sync.Mutex
	requests []string
	images   []*image
	objects  map[string]object
	work     map[string]int
	workIDs  map[string]string
	schemas  []schema
	shapes   map[string][]shape
}

// Start runs a stand-in region whose first imported image is imageID. It is
// closed when the test ends.
func Start(t testing.TB, imageID string) *Server {
	t.Helper()
	s := &Server{imageID: imageID, created: time.Now().UTC().Truncate(time.Second), objects: map[string]object{},
		work: map[string]int{}, workIDs: map[string]string{}, shapes: map[string][]shape{}}
	server := httptest.NewServer(s.handler())
	t.Cleanup(server.Close)
	s.URL = server.URL
	return s
}

// Requests returns every request served so far as "METHOD /path".
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// Count returns how many served requests start with prefix.
func (s *Server) Count(prefix string) int {
	count := 0
	for _, request := range s.Requests() {
		if strings.HasPrefix(request, prefix) {
			count++
		}
	}
	return count
}

// Object returns a stored object's bytes and user metadata.
func (s *Server) Object(namespace, bucket, name string) ([]byte, map[string]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.objects[namespace+"/"+bucket+"/"+name]
	return stored.data, stored.metadata, ok
}

// Image returns the lifecycle state of a stored image.
func (s *Server) Image(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, stored := range s.images {
		if stored.ID == id {
			return stored.State, true
		}
	}
	return "", false
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("opc-request-id", "standin")
	w.WriteHeader(status)
	if value != nil {
		_ = json.MarshalWrite(w, value)
	}
}

func refuse(w http.ResponseWriter, status int, code, message string) {
	reply(w, status, map[string]string{"code": code, "message": message})
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	const core = "/20160918"
	mux.HandleFunc("HEAD /n/{namespace}/b/{bucket}/o/{object...}", s.headObject)
	mux.HandleFunc("PUT /n/{namespace}/b/{bucket}/o/{object...}", s.putObject)
	mux.HandleFunc("GET "+core+"/images", s.listImages)
	mux.HandleFunc("POST "+core+"/images", s.createImage)
	mux.HandleFunc("GET "+core+"/images/{id}", s.getImage)
	mux.HandleFunc("GET "+core+"/workRequests/{id}", s.getWorkRequest)
	mux.HandleFunc("GET "+core+"/computeImageCapabilitySchemas", s.listSchemas)
	mux.HandleFunc("POST "+core+"/computeImageCapabilitySchemas", s.createSchema)
	mux.HandleFunc("GET "+core+"/computeImageCapabilitySchemas/{id}", s.getSchema)
	mux.HandleFunc("GET "+core+"/computeGlobalImageCapabilitySchemas", func(w http.ResponseWriter, r *http.Request) {
		// The first page is empty and points at the next one, so the
		// client must follow pagination to find the schema.
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("opc-next-page", "global-schemas-2")
			reply(w, http.StatusOK, []map[string]string{})
			return
		}
		reply(w, http.StatusOK, []map[string]string{{"id": "ocid1.computeglobalimgcapschema.standin", "currentVersionName": "standin-v1"}})
	})
	mux.HandleFunc("GET "+core+"/images/{id}/shapes", s.listShapes)
	mux.HandleFunc("PUT "+core+"/images/{id}/shapes/{shape}", s.addShape)
	mux.HandleFunc("DELETE "+core+"/images/{id}/shapes/{shape}", s.removeShape)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every SDK request is signed; an unsigned request is not the client
		// under test.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			refuse(w, http.StatusUnauthorized, "NotAuthenticated", "unsigned request")
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		mux.ServeHTTP(w, r)
	})
}

func objectKey(r *http.Request) string {
	return r.PathValue("namespace") + "/" + r.PathValue("bucket") + "/" + r.PathValue("object")
}

func (s *Server) headObject(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	stored, ok := s.objects[objectKey(r)]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	for key, value := range stored.metadata {
		w.Header().Set("opc-meta-"+key, value)
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(stored.data)))
	w.Header().Set("ETag", "standin")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameter", err.Error())
		return
	}
	metadata := map[string]string{}
	for key, values := range r.Header {
		if name, ok := strings.CutPrefix(strings.ToLower(key), "opc-meta-"); ok && len(values) > 0 {
			metadata[name] = values[0]
		}
	}
	key := objectKey(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[key]; exists && r.Header.Get("If-None-Match") == "*" {
		refuse(w, http.StatusPreconditionFailed, "IfNoneMatchFailed", "object exists")
		return
	}
	s.objects[key] = object{data: data, metadata: metadata}
	w.Header().Set("ETag", "standin")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) find(id string) *image {
	for _, stored := range s.images {
		if stored.ID == id {
			return stored
		}
	}
	return nil
}

func (s *Server) listImages(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	matches := []image{}
	for _, stored := range s.images {
		if stored.CompartmentID == query.Get("compartmentId") && (query.Get("displayName") == "" || stored.DisplayName == query.Get("displayName")) {
			matches = append(matches, *stored)
		}
	}
	reply(w, http.StatusOK, matches)
}

type createImage struct {
	CompartmentID string `json:"compartmentId"`
	DisplayName   string `json:"displayName"`
	LaunchMode    string `json:"launchMode"`
	Source        struct {
		Type            string `json:"sourceType"`
		Namespace       string `json:"namespaceName"`
		Bucket          string `json:"bucketName"`
		Object          string `json:"objectName"`
		SourceImageType string `json:"sourceImageType"`
	} `json:"imageSourceDetails"`
}

func (s *Server) createImage(w http.ResponseWriter, r *http.Request) {
	var request createImage
	if err := json.UnmarshalRead(r.Body, &request); err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameter", err.Error())
		return
	}
	if r.Header.Get("opc-retry-token") == "" || request.Source.Type != "objectStorageTuple" || request.Source.SourceImageType != "QCOW2" || request.LaunchMode != "PARAVIRTUALIZED" {
		refuse(w, http.StatusBadRequest, "InvalidParameter", "unexpected CreateImage request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[request.Source.Namespace+"/"+request.Source.Bucket+"/"+request.Source.Object]; !ok {
		refuse(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "source object not found")
		return
	}
	id := s.imageID
	if len(s.images) > 0 {
		id = fmt.Sprintf("%s.%d", s.imageID, len(s.images))
	}
	created := &image{ID: id, CompartmentID: request.CompartmentID, DisplayName: request.DisplayName, State: "IMPORTING",
		Billable: BillableSizeGB, TimeCreated: s.created.Format(time.RFC3339)}
	s.images = append(s.images, created)
	work := fmt.Sprintf("ocid1.coreservicesworkrequest.standin.%d", len(s.work)+1)
	s.work[work] = WorkRequestPolls
	s.workIDs[work] = id
	w.Header().Set("opc-work-request-id", work)
	reply(w, http.StatusOK, created)
}

func (s *Server) getImage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := s.find(r.PathValue("id"))
	if stored == nil {
		refuse(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "image not found")
		return
	}
	reply(w, http.StatusOK, stored)
}

func (s *Server) getWorkRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining, ok := s.work[id]
	if !ok {
		refuse(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "work request not found")
		return
	}
	status := "SUCCEEDED"
	if remaining > 0 {
		status = "IN_PROGRESS"
		s.work[id] = remaining - 1
	} else if stored := s.find(s.workIDs[id]); stored != nil {
		stored.State = "AVAILABLE"
	}
	reply(w, http.StatusOK, map[string]any{"id": id, "operationType": "ImportImage", "status": status,
		"compartmentId": "standin", "percentComplete": 0, "timeAccepted": s.created.Format(time.RFC3339)})
}

func (s *Server) listSchemas(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	summaries := []map[string]string{}
	for _, stored := range s.schemas {
		if stored.CompartmentID == query.Get("compartmentId") && stored.ImageID == query.Get("imageId") {
			summaries = append(summaries, map[string]string{"id": stored.ID, "displayName": stored.DisplayName,
				"computeGlobalImageCapabilitySchemaVersionName": stored.Version, "timeCreated": stored.TimeCreated})
		}
	}
	reply(w, http.StatusOK, summaries)
}

func (s *Server) createSchema(w http.ResponseWriter, r *http.Request) {
	var request schema
	if err := json.UnmarshalRead(r.Body, &request); err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameter", err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.find(request.ImageID) == nil {
		refuse(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "image not found")
		return
	}
	request.ID = fmt.Sprintf("ocid1.computeimgcapschema.standin.%d", len(s.schemas)+1)
	request.TimeCreated = s.created.Format(time.RFC3339)
	s.schemas = append(s.schemas, request)
	reply(w, http.StatusOK, request)
}

func (s *Server) getSchema(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, stored := range s.schemas {
		if stored.ID == r.PathValue("id") {
			reply(w, http.StatusOK, stored)
			return
		}
	}
	refuse(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "schema not found")
}

func (s *Server) listShapes(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.shapes[r.PathValue("id")]
	if entries == nil {
		entries = []shape{}
	}
	reply(w, http.StatusOK, entries)
}

func (s *Server) addShape(w http.ResponseWriter, r *http.Request) {
	var request struct {
		OCPU   *jsontext.Value `json:"ocpuConstraints,omitempty"`
		Memory *jsontext.Value `json:"memoryConstraints,omitempty"`
	}
	if err := json.UnmarshalRead(r.Body, &request); err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameter", err.Error())
		return
	}
	id, name := r.PathValue("id"), r.PathValue("shape")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.find(id) == nil {
		refuse(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "image not found")
		return
	}
	entry := shape{ImageID: id, Shape: name, OCPU: request.OCPU, Memory: request.Memory}
	entries := slices.DeleteFunc(s.shapes[id], func(existing shape) bool { return existing.Shape == name })
	s.shapes[id] = append(entries, entry)
	reply(w, http.StatusOK, entry)
}

func (s *Server) removeShape(w http.ResponseWriter, r *http.Request) {
	id, name := r.PathValue("id"), r.PathValue("shape")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shapes[id] = slices.DeleteFunc(s.shapes[id], func(existing shape) bool { return existing.Shape == name })
	w.WriteHeader(http.StatusNoContent)
}

var signingKey = sync.OnceValues(func() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil
})

// Client returns the real in-binary SDK client for region, signing with a
// throwaway key and pinned to the stand-in at endpoint.
func Client(endpoint, region string) (imageimport.API, error) {
	key, err := signingKey()
	if err != nil {
		return nil, err
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..standin", "ocid1.user.oc1..standin", region,
		"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", key, nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: region,
		Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		return nil, err
	}
	return imageimport.NewClient(factory, endpoint)
}

// Importer returns an ImporterFactory whose importers drive the real SDK
// client against the stand-in at endpoint, polling every millisecond.
func Importer(endpoint string) imageimport.ImporterFactory {
	return func(region string) (imageimport.Importer, error) {
		client, err := Client(endpoint, region)
		if err != nil {
			return imageimport.Importer{}, err
		}
		return imageimport.Importer{Client: client, PollInterval: time.Millisecond, MaxPollInterval: 5 * time.Millisecond,
			AvailabilityTimeout: time.Minute}, nil
	}
}
