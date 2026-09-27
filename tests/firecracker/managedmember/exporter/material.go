package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
)

func exportMember(root string, index int, authority []byte, public ed25519.PublicKey, configurationID, schemaDigest string,
	member, client memberCertificate, memberCAPEM, clientCAPEM, registry []byte, token, sourceDigest string,
) (memberPacket, error) {
	name := []string{"a", "b"}[index]
	directory := filepath.Join(root, "member-"+name)
	if err := os.Mkdir(directory, 0700); err != nil {
		return memberPacket{}, err
	}
	inputs := make(map[string]inputFile, 14)
	add := func(key, filename string, contents []byte) error {
		path := filepath.Join(directory, filename)
		if err := writeExclusive(path, contents); err != nil {
			return err
		}
		entry, err := record(path)
		if err != nil {
			return err
		}
		inputs[key] = entry
		return nil
	}
	for _, item := range []struct {
		key, filename string
		contents      []byte
	}{
		{"authority_tbca", "authority.tbca", authority},
		{"trusted_public_key", "trusted-public-key", public},
		{"server_crt", "server.crt", member.chain},
		{"server_key", "server.key", member.key},
		{"client_ca_pem", "client-ca.pem", memberCAPEM},
		{"server_ca_pem", "server-ca.pem", memberCAPEM},
		{"client_chain", "client-chain.pem", client.chain},
		{"client_private_key", "client-private-key.pem", client.key},
		{"client_api_keys", "client-api-keys.json", registry},
		{"client_api_token", "client-api-token", []byte(token)},
		{"client_https_ca_pem", "client-https-ca.pem", clientCAPEM},
	} {
		if err := add(item.key, item.filename, item.contents); err != nil {
			return memberPacket{}, err
		}
	}
	material := filepath.Join(memberDirs[index], "material")
	config, err := json.Marshal(map[string]any{
		"version": 1, "listen_addr": "127.0.0.1:9465",
		"certificate_chain":    filepath.Join(material, "client-chain.pem"),
		"private_key":          filepath.Join(material, "client-private-key.pem"),
		"api_key_registry":     filepath.Join(material, "client-api-keys.json"),
		"handshake_timeout_ms": 1000,
	})
	if err != nil {
		return memberPacket{}, err
	}
	if err := add("client_config", "client-config.json", config); err != nil {
		return memberPacket{}, err
	}
	managedManifest, err := json.Marshal(map[string]any{
		"version":                  1,
		"client_config_sha256":     inputs["client_config"].SHA256,
		"certificate_chain_sha256": inputs["client_chain"].SHA256,
		"private_key_sha256":       inputs["client_private_key"].SHA256,
		"api_key_registry_sha256":  inputs["client_api_keys"].SHA256,
	})
	if err != nil {
		return memberPacket{}, err
	}
	if err := add("client_managed_manifest", "client-managed-manifest.json", managedManifest); err != nil {
		return memberPacket{}, err
	}
	volumePath := filepath.Join(directory, "volume.ext4")
	if err := makeVolume(volumePath, volumeUUIDs[index]); err != nil {
		return memberPacket{}, err
	}
	inputs["volume_ext4"], err = record(volumePath)
	if err != nil {
		return memberPacket{}, err
	}
	other := 1 - index
	leafHash := sha256.Sum256(member.leaf)
	bound := map[string]any{
		"version":        1,
		"node":           "node-" + name,
		"failure_domain": failureDomains[index],
		"member": map[string]any{"host_attempt": 1, "scope": map[string]any{
			"cluster_id": clusterID, "tenant_id": tenantID, "database_id": databaseID,
			"shard_id": 1, "member_id": memberIDs[index], "incarnation": memberIncarnations[index],
		}},
		"authority": map[string]any{
			"epoch": 1, "configuration_id": configurationID,
			"certificate_sha256": inputs["authority_tbca"].SHA256,
			"tls_leaf_sha256":    hex.EncodeToString(leafHash[:]),
		},
		"runtime": map[string]any{
			"device_path": "/dev/oracleoci/oraclevdb", "mount_path": filepath.Join(memberDirs[index], "volume"),
			"filesystem_uuid": volumeUUIDs[index], "filesystem_type": "ext4",
			"trusted_key_sha256":                      inputs["trusted_public_key"].SHA256,
			"server_certificate_sha256":               inputs["server_crt"].SHA256,
			"server_private_key_sha256":               inputs["server_key"].SHA256,
			"client_ca_roots_sha256":                  inputs["client_ca_pem"].SHA256,
			"client_managed_material_manifest_sha256": inputs["client_managed_manifest"].SHA256,
			"replication_listen_address":              guestIPs[index] + ":7000",
			"replication_peer_member_id":              memberIDs[other],
			"replication_peer_address":                guestIPs[other] + ":7000",
			"replication_server_ca_sha256":            inputs["server_ca_pem"].SHA256,
		},
		"volume_id":            "ocid1.volume.fixture-" + name,
		"attachment_id":        "ocid1.volumeattachment.fixture-" + name,
		"attachment_etag":      "fixture-attachment-" + name,
		"source_digest":        sourceDigest,
		"system_reserve_bytes": uint64(1 << 30),
		"collection_id":        collectionID,
		"schema_generation":    1,
		"schema_digest":        schemaDigest,
		"document_id":          documentID,
	}
	if len(inputs) != 14 {
		return memberPacket{}, fmt.Errorf("member %s packet has %d inputs", name, len(inputs))
	}
	return memberPacket{Inputs: inputs, GuestConfig: bound}, nil
}
