package drainwire

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"time"
)

// VerifyPoolReceiptStops verifies retained raw execution proofs, not authority to
// retire. HOME separately loads the protected object and current signed source.
// The producer may call this before committing the final stopped phase.
func VerifyPoolReceiptStops(receipt PoolReceipt, now time.Time) error {
	if receipt.Validate() != nil || now.Before(receipt.CapturedAt) || !now.Before(receipt.ExpiresAt) ||
		len(receipt.Stops) != len(receipt.Holds) {
		return errors.New("pool drain has no complete current exact execution-stop evidence")
	}
	for index, signed := range receipt.Holds {
		verified := false
		for _, certificate := range receipt.ManagerCertificates {
			if VerifySignedHold(signed, certificate, receipt.ClusterCAPEM, receipt.ClusterID, now) == nil {
				verified = true
				break
			}
		}
		if !verified {
			return errors.New("pool drain retained hold has no captured actual manager signature")
		}
		challenge := receipt.Challenges[index]
		stopIndex := slices.IndexFunc(receipt.Stops, func(stop SignedStop) bool { return stop.Challenge == challenge })
		if stopIndex < 0 {
			return errors.New("pool drain lost an exact execution-stop observation")
		}
		if err := VerifySignedStop(receipt.Stops[stopIndex], challenge, receipt.WorkerCertificate, receipt.ClusterCAPEM, receipt.ClusterID, now); err != nil {
			return err
		}
	}
	block, _ := pem.Decode(receipt.WorkerCertificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("pool drain captured worker certificate is unavailable")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if certificate.Subject.CommonName != receipt.NodeID {
		return errors.New("pool drain worker certificate differs from exact captured node")
	}
	return nil
}
