package vmcontrolseed

import "errors"

const RegionalCaptureNKeyPath = Directory + "/regional/source-capture.seed"
const GlobalCaptureNKeyPath = Directory + "/global/source-capture.seed"
const CaptureCertificatePath = Directory + "/capture/client.pem"
const CapturePrivateKeyPath = Directory + "/capture/client.key"
const CaptureRequestPath = Directory + "/capture/request.json"
const CaptureOutputPath = "/var/lib/terrascale/orchestrator/capture"

// PreliminaryCaptureDeclaration explicitly enables the source's privileged
// local capture worker. No source account credentials are given to candidates.
type PreliminaryCaptureDeclaration struct {
	MaxSnapshotBytes int64
	MaxTotalBytes    int64
}

// GenerateGRUWithPreliminaryCapture creates a new owner-admitted launch with
// source-only capture credentials and bounded staging capacity. GenerateGRU
// remains the default without this capability; old signed launches gain none.
func GenerateGRUWithPreliminaryCapture(runID string, guests []Guest, declaration PreliminaryCaptureDeclaration) (map[string]Material, error) {
	if err := declaration.Validate(); err != nil {
		return nil, err
	}
	return generateGRU(runID, guests, &declaration)
}

func (declaration PreliminaryCaptureDeclaration) Validate() error {
	if declaration.MaxSnapshotBytes < 1024 || declaration.MaxSnapshotBytes > 1<<30 || declaration.MaxTotalBytes < declaration.MaxSnapshotBytes || declaration.MaxTotalBytes > 256<<30 {
		return errors.New("vmcontrolseed: invalid explicit preliminary capture capacity")
	}
	return nil
}
