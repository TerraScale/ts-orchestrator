package vmimage

// The schemas in this file use the token-level validator shared with guest
// seeds. encoding/json deliberately accepts duplicate and case-insensitive
// field names, which is unsuitable for persisted cache trust boundaries.

func manifestJSONSchema() *seedJSONObjectSchema {
	transform := &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"type": {}, "sectorSize": {}, "startSector": {}, "sectorCount": {},
		},
		required: []string{"type", "sectorSize", "startSector", "sectorCount"},
	}
	artifact := &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"name": {}, "architecture": {}, "version": {}, "source": {},
			"sha256": {}, "size": {}, "mode": {}, "inputSha256": {},
			"inputSize": {}, "transform": {object: transform},
		},
		required: []string{"name", "architecture", "version", "source", "sha256", "size", "mode"},
	}
	return &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"schemaVersion": {}, "ubuntuRelease": {}, "architecture": {},
			"version": {}, "kernel": {object: artifact}, "rootfs": {object: artifact},
		},
		required: []string{"schemaVersion", "ubuntuRelease", "architecture", "version", "kernel", "rootfs"},
	}
}

func buildPlanJSONSchema() *seedJSONObjectSchema {
	step := &seedJSONObjectSchema{
		fields:   map[string]seedJSONFieldSchema{"name": {}, "inputs": {}, "output": {}},
		required: []string{"name", "inputs", "output"},
	}
	return &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"schemaVersion": {}, "ubuntuRelease": {}, "architecture": {}, "version": {},
			"manifest": {object: manifestJSONSchema()}, "manifestDigest": {}, "cacheKey": {},
			"steps": {objectArray: step},
		},
		required: []string{"schemaVersion", "ubuntuRelease", "architecture", "version", "manifest", "manifestDigest", "cacheKey", "steps"},
	}
}

func toolchainJSONSchema() *seedJSONObjectSchema {
	remote := &seedJSONObjectSchema{
		fields:   map[string]seedJSONFieldSchema{"url": {}, "sha256": {}, "size": {}},
		required: []string{"url", "sha256", "size"},
	}
	member := &seedJSONObjectSchema{
		fields:   map[string]seedJSONFieldSchema{"archivePath": {}, "name": {}, "sha256": {}, "size": {}, "mode": {}},
		required: []string{"archivePath", "name", "sha256", "size", "mode"},
	}
	return &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"schemaVersion": {}, "architecture": {}, "firecrackerVersion": {},
			"archive": {object: remote}, "firecracker": {object: member}, "jailer": {object: member},
			"sdkModule": {}, "sdkVersion": {},
		},
		required: []string{"schemaVersion", "architecture", "firecrackerVersion", "archive", "firecracker", "jailer", "sdkModule", "sdkVersion"},
	}
}

func preparationReceiptJSONSchema() *seedJSONObjectSchema {
	return &seedJSONObjectSchema{
		fields: map[string]seedJSONFieldSchema{
			"schemaVersion": {}, "manifestDigest": {}, "architecture": {}, "ubuntuRelease": {},
			"osId": {}, "osVersionId": {}, "osVersion": {}, "rootfsSha256": {},
			"sanitizedMounts": {}, "filesystemCheck": {},
		},
		required: []string{"schemaVersion", "manifestDigest", "architecture", "ubuntuRelease", "osId", "osVersionId", "osVersion", "rootfsSha256", "sanitizedMounts", "filesystemCheck"},
	}
}
