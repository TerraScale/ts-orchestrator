package nativerootoci

import (
	"encoding/json/v2"
	"errors"
)

const maxSignedConfigBytes = 16 << 10

type signedConfig struct {
	Version       uint64 `json:"version"`
	AckProfile    string `json:"ack_profile"`
	Bucket        string `json:"bucket"`
	Region        string `json:"region"`
	Endpoint      string `json:"endpoint,omitempty"`
	NativeOCIRoot *struct {
		Namespace string `json:"namespace"`
	} `json:"native_oci_root,omitempty"`
}

// TargetFromSignedConfig accepts only the host's SHA-verified member material.
// A generic S3 target returns selected=false; its existing RustFS path remains
// independent of the optional native helper.
func TargetFromSignedConfig(wire []byte, targetDigest, publicationDigest string) (target Target, selected bool, err error) {
	if len(wire) == 0 || len(wire) > maxSignedConfigBytes {
		return Target{}, false, errors.New("signed native OCI target material has invalid size")
	}
	var config signedConfig
	if err := json.Unmarshal(wire, &config, json.RejectUnknownMembers(true)); err != nil ||
		config.Version != 1 || config.AckProfile != "object_durable" {
		return Target{}, false, errors.New("signed native OCI target material is invalid")
	}
	if config.NativeOCIRoot == nil {
		return Target{}, false, nil
	}
	target, err = NewTarget(config.Region, config.NativeOCIRoot.Namespace, config.Bucket,
		config.Endpoint, publicationDigest, targetDigest)
	if err != nil {
		return Target{}, false, err
	}
	return target, true, nil
}
