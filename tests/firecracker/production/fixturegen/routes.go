package fixturegen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// CapturedObjectRoute asks the generated OCI SDK request type for its exact
// GET URI. The object key and response body come from the capture client.
func CapturedObjectRoute(controller Controller, object CapturedObject) (Route, error) {
	if controller.Slot == "" || controller.InstanceOCID == "" || object.Namespace == "" ||
		object.Bucket == "" || object.ObjectName == "" || len(object.Body) == 0 ||
		object.ETag == "" || object.LastModified.IsZero() {
		return Route{}, errors.New("captured object lacks route identity or response metadata")
	}
	uri, err := sdkObjectRequestURI(object.Namespace, object.Bucket, object.ObjectName)
	if err != nil {
		return Route{}, err
	}
	digest := sha256.Sum256(object.Body)
	return Route{ControllerSlot: controller.Slot, InstanceOCID: controller.InstanceOCID,
		Host: "objectstorage.sa-saopaulo-1.oraclecloud.com", RequestURI: uri,
		Status: http.StatusOK, BodyPath: "simulator/responses/" + hex.EncodeToString(digest[:]) + ".json",
		ETag: object.ETag, LastModified: object.LastModified}, nil
}

func CapturedMissingRoute(controller Controller, missing CapturedMissing) (Route, error) {
	if controller.Slot == "" || controller.InstanceOCID == "" || missing.Namespace == "" ||
		missing.Bucket == "" || missing.ObjectName == "" {
		return Route{}, errors.New("captured missing read lacks exact identity")
	}
	uri, err := sdkObjectRequestURI(missing.Namespace, missing.Bucket, missing.ObjectName)
	if err != nil {
		return Route{}, err
	}
	return Route{ControllerSlot: controller.Slot, InstanceOCID: controller.InstanceOCID,
		Host: "objectstorage.sa-saopaulo-1.oraclecloud.com", RequestURI: uri,
		Status: http.StatusNotFound}, nil
}

func sdkObjectRequestURI(namespace, bucket, objectName string) (string, error) {
	request, err := (objectstorage.GetObjectRequest{NamespaceName: new(namespace),
		BucketName: new(bucket), ObjectName: new(objectName)}).HTTPRequest(
		http.MethodGet, "/n/{namespaceName}/b/{bucketName}/o/{objectName}", nil, nil)
	if err != nil {
		return "", fmt.Errorf("construct OCI SDK exact object GET: %w", err)
	}
	return request.URL.RequestURI(), nil
}
