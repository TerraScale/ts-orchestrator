package bootstrapstart

import "github.com/TerraScale/ts-orchestrator/internal/identityrekey"

// VerifyIdentityRekeyBinaryFile measures a proposed file without publication.
func VerifyIdentityRekeyBinaryFile(path string, pin identityrekey.BinaryPin) error {
	_, err := verifyAcceptedBinaryFile(path, pin)
	return err
}
