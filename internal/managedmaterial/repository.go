package managedmaterial

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var (
	ErrMaterialConflict = errors.New("managed material object conflicts with its immutable generation")
	ErrMaterialUnknown  = errors.New("managed material object outcome is unknown")
	ErrMaterialNotFound = errors.New("managed material object was not found")
)

// RepositoryConfig must come from independently signed regional configuration.
// OCI IAM must allow exact-object create and read, and deny overwrite, delete,
// and list to the controller principal. This type cannot grant those IAM rights.
type RepositoryConfig struct {
	Region    oci.Region
	Cell      string
	Namespace string
	Bucket    string
	KMSKeyID  string
}

type ObjectClient interface {
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
}

type ObjectReference struct {
	Name       string `json:"name"`
	VersionID  string `json:"version_id"`
	ETag       string `json:"etag"`
	SHA256     string `json:"sha256"`
	SpecSHA256 string `json:"spec_sha256"`
}

type Repository struct {
	config RepositoryConfig
	client ObjectClient
	fencer authority.Fencer
}
