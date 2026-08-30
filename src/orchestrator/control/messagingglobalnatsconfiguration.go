// Port of src/TerraScale.Orchestrator/Messaging/GlobalNatsConfiguration.cs.
package control

import (
	"errors"
	"net/url"
	"strings"
)

// GlobalNatsConfiguration mirrors the C# sealed class.
type GlobalNatsConfiguration struct {
	Url            string
	Authentication *NatsAuthenticationFiles
	Tls            *NatsTlsFiles
}

// NKeyFile mirrors the C# NKeyFile property.
func (c *GlobalNatsConfiguration) NKeyFile() *string { return c.Authentication.NKeyFile }

// GlobalNatsConfigurationIsLegacyAuthorityAliasAllowed mirrors the C# pure
// check: the legacy TS_ORCH_GLOBAL_NATS_* settings identify GRU global
// authority.
func GlobalNatsConfigurationIsLegacyAuthorityAliasAllowed(cell string) bool {
	return cell == "gru" && GlobalNatsTopologyIsCellToken(cell)
}

// GlobalNatsConfigurationValidateLegacyAuthorityAlias mirrors the C# thrower.
func GlobalNatsConfigurationValidateLegacyAuthorityAlias(cell string) error {
	if !GlobalNatsConfigurationIsLegacyAuthorityAliasAllowed(cell) {
		return errors.New(
			"TS_ORCH_GLOBAL_NATS_* is a GRU-only global-authority alias. (Parameter 'cell')")
	}

	return nil
}

// GlobalNatsConfigurationResolve mirrors the C# Resolve overload without a
// credentials file.
func GlobalNatsConfigurationResolve(
	rawUrl string,
	nkeyFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	replicas int,
	cell string,
) (*GlobalNatsConfiguration, error) {
	return GlobalNatsConfigurationResolveWithCredentials(
		rawUrl, nkeyFile, "", caFile, certificateFile, keyFile, replicas, cell)
}

// GlobalNatsConfigurationResolveWithCredentials mirrors the full C# Resolve.
func GlobalNatsConfigurationResolveWithCredentials(
	rawUrl string,
	nkeyFile string,
	credentialsFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	replicas int,
	cell string,
) (*GlobalNatsConfiguration, error) {
	values := []string{rawUrl, nkeyFile, credentialsFile, caFile, certificateFile, keyFile}
	supplied := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			supplied++
		}
	}

	if supplied > 0 && cell != "" {
		if err := GlobalNatsConfigurationValidateLegacyAuthorityAlias(cell); err != nil {
			return nil, err
		}
	}

	if supplied == 0 {
		return nil, nil
	}

	authentication, err := NatsAuthenticationFilesResolve(nkeyFile, credentialsFile, "TS_ORCH_GLOBAL_NATS")
	if err != nil {
		return nil, err
	}

	if rawUrl == "" || authentication == nil || caFile == "" || certificateFile == "" || keyFile == "" {
		return nil, errors.New(
			"Global control NATS requires URL, authentication, CA, certificate, and key together.")
	}

	if replicas != 3 {
		return nil, errors.New("Global control NATS requires exactly three replicas.")
	}

	parsed, err := url.Parse(rawUrl)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "tls" {
		return nil, errors.New("TS_ORCH_GLOBAL_NATS_URL must be an absolute tls:// URL.")
	}

	tls, err := NatsTlsFilesResolve(caFile, certificateFile, keyFile, "TS_ORCH_GLOBAL_NATS_TLS")
	if err != nil {
		return nil, err
	}

	if tls == nil {
		return nil, errors.New("TS_ORCH_GLOBAL_NATS_TLS credentials are missing.")
	}

	return &GlobalNatsConfiguration{
		Url:            parsed.String(),
		Authentication: authentication,
		Tls:            tls,
	}, nil
}
