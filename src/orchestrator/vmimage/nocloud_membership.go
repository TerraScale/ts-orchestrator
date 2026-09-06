package vmimage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentity"

	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
)

const MembershipIdentityPath = "/etc/terrascale/orchestrator/identity.pem"
const MembershipPinsPath = "/etc/terrascale/orchestrator/membership-pins.json"
const membershipServiceUser = "terrascale-orchestrator"

func canonicalMembershipBootstrap(input TSNodeBootstrap) ([]byte, []byte, error) {
	_, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(input.MembershipIdentityPrivateKey)
	if err != nil {
		return nil, nil, errors.New("vmimage: invalid private guest membership identity")
	}
	if len(input.MembershipPins) == 0 || len(input.MembershipPins) > 640 || input.MembershipPins[input.Config.NodeID] != public {
		return nil, nil, errors.New("vmimage: guest membership pins do not bind its preissued identity")
	}
	for instance, pin := range input.MembershipPins {
		if !instanceIDPattern.MatchString(instance) || !validMembershipBootstrapPin(pin) {
			return nil, nil, errors.New("vmimage: invalid guest membership pin entry")
		}
	}
	pins, err := json.Marshal(input.MembershipPins)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), input.MembershipIdentityPrivateKey...), pins, nil
}

// Root files are staged as root before boot. The declared final principal is
// created and the private file ownership is verified before ts-node starts.
func membershipOwnershipBootstrap() string {
	return serviceidentity.Bootstrap(membershipServiceUser) +
		"/usr/bin/chown " + membershipServiceUser + ":" + membershipServiceUser + " " + MembershipIdentityPath + "\n" +
		"/usr/bin/chmod 0400 " + MembershipIdentityPath + "\n" +
		"/usr/bin/test \"$(/usr/bin/stat -c %U:%G:%a " + MembershipIdentityPath + ")\" = " + membershipServiceUser + ":" + membershipServiceUser + ":400\n"
}

func validMembershipBootstrapPin(pin string) bool {
	if len(pin) == 0 || len(pin) > 512 {
		return false
	}
	der, err := base64.StdEncoding.Strict().DecodeString(pin)
	if err != nil || base64.StdEncoding.EncodeToString(der) != pin {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	public, ok := key.(*ecdsa.PublicKey)
	return ok && public.Curve == elliptic.P256() && public.Curve.IsOnCurve(public.X, public.Y)
}
