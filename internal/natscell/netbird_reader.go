package natscell

import (
	"errors"
	"slices"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// NetBirdReaderPublishes names fixed, protected read cursors. In particular,
// TRUST_ROOTS also contains configuration material, so MSG.GET is not public.
func NetBirdReaderPublishes(cell string) jwt.StringList {
	if !cellName.MatchString(cell) {
		return nil
	}
	grants := jwt.StringList{protocol.Regional(cell, "netbird", "read-open")}
	for _, source := range [][2]string{
		{"TS_CONTROL_LOG", "NET_ACCOUNT_READ"},
		{"KV_TS_SERVICE_SET", "NET_SERVICE_SET_READ"},
		{"KV_TS_TRUST_ROOTS", "NET_TRUST_ROOT_READ"},
	} {
		grants.Add("$JS.API.STREAM.INFO."+source[0],
			"$JS.API.CONSUMER.INFO."+source[0]+"."+source[1],
			"$JS.API.CONSUMER.MSG.NEXT."+source[0]+"."+source[1])
	}
	return grants
}

// ValidateNetBirdReaderCredentialBytes checks the closed TCP-only reader role.
// The signed source separately pins its issuer, generation and original expiry.
func ValidateNetBirdReaderCredentialBytes(data []byte, cell string) error {
	if !cellName.MatchString(cell) {
		return errors.New("NetBird reader cell is invalid")
	}
	raw, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return err
	}
	user, err := jwt.ParseDecoratedUserNKey(data)
	if err != nil {
		return err
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil || public != claim.Subject || !nkeys.IsValidPublicAccountKey(claim.IssuerAccount) ||
		!nkeys.IsValidPublicAccountKey(claim.Issuer) || claim.Issuer == claim.IssuerAccount ||
		claim.Name != "netbird-manager-read" || claim.Expires <= claim.IssuedAt || claim.NotBefore != 0 ||
		claim.BearerToken || claim.ProxyRequired || len(claim.Src) != 0 || len(claim.Tags) != 0 ||
		!slices.Equal(claim.AllowedConnectionTypes, jwt.StringList{jwt.ConnectionTypeStandard}) ||
		!slices.Equal(claim.Pub.Allow, NetBirdReaderPublishes(cell)) ||
		!slices.Equal(claim.Sub.Allow, jwt.StringList{protocol.InboxGrant(cell, public)}) ||
		len(claim.Pub.Deny) != 0 || len(claim.Sub.Deny) != 0 || claim.Resp != nil {
		return errors.New("NetBird reader credentials differ from the fixed finite read role")
	}
	return nil
}
