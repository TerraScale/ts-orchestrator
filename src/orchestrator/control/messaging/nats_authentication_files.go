package messaging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// NatsAuthenticationFiles is one resolved authentication identity — either an
// NKey seed file or a NATS credentials file — plus its public key.
type NatsAuthenticationFiles struct {
	NKeyFile        *string
	CredentialsFile *string
	PublicKey       string
}

// NatsAuthenticationFilesResolve mirrors NatsAuthenticationFiles.Resolve. A
// nil result with a nil error means no authentication was supplied.
func NatsAuthenticationFilesResolve(
	nkeyFile string,
	credentialsFile string,
	optionPrefix string,
) (*NatsAuthenticationFiles, error) {
	hasNkey := strings.TrimSpace(nkeyFile) != ""
	hasCredentials := strings.TrimSpace(credentialsFile) != ""
	if !hasNkey && !hasCredentials {
		return nil, nil
	}

	if hasNkey && hasCredentials {
		return nil, fmt.Errorf(
			"%s requires either an NKey seed file or a credentials file, not both.", optionPrefix)
	}

	if hasNkey {
		path, err := NatsCredentialFile.Resolve(nkeyFile, optionPrefix+"_NKEY_FILE")
		if err != nil {
			return nil, err
		}

		if path == "" {
			return nil, fmt.Errorf("%s_NKEY_FILE must identify a bounded existing NKey seed file.", optionPrefix)
		}

		publicKey, err := NatsCredentialFile.PublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("%s_NKEY_FILE does not contain a valid NKey seed.", optionPrefix)
		}

		return &NatsAuthenticationFiles{NKeyFile: &path, PublicKey: publicKey}, nil
	}

	resolvedCredentials, err := natsAuthenticationResolvePrivateFile(credentialsFile,
		optionPrefix+"_CREDENTIALS_FILE")
	if err != nil {
		return nil, err
	}

	seed, err := natsAuthenticationReadCredentialsSeed(resolvedCredentials, optionPrefix)
	if err != nil {
		return nil, err
	}

	seedPair, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nil, fmt.Errorf("%s_CREDENTIALS_FILE does not contain a valid user NKey seed.", optionPrefix)
	}

	publicKey, err := seedPair.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("%s_CREDENTIALS_FILE does not contain a valid user NKey seed.", optionPrefix)
	}

	return &NatsAuthenticationFiles{CredentialsFile: &resolvedCredentials, PublicKey: publicKey}, nil
}

// NatsAuthenticationFilesFromCredentialsFile resolves a required credentials
// file into its authentication identity.
func NatsAuthenticationFilesFromCredentialsFile(credentialsFile, optionPrefix string) (*NatsAuthenticationFiles, error) {
	resolved, err := NatsAuthenticationFilesResolve("", credentialsFile, optionPrefix)
	if err != nil {
		return nil, err
	}

	if resolved == nil {
		return nil, fmt.Errorf("%s_CREDENTIALS_FILE is required.", optionPrefix)
	}

	return resolved, nil
}

// NatsAuthenticationFilesFromNKeyFile resolves an NKey seed file into its
// authentication identity, exposing the public key derived from the seed
// rather than the path.
func NatsAuthenticationFilesFromNKeyFile(nkeyFile string) (*NatsAuthenticationFiles, error) {
	if strings.TrimSpace(nkeyFile) == "" {
		return nil, errors.New("The NKey file path is required.")
	}

	publicKey, err := NatsCredentialFile.PublicKey(nkeyFile)
	if err != nil {
		return nil, errors.New("The NKey file does not contain a valid NKey seed.")
	}

	return &NatsAuthenticationFiles{NKeyFile: &nkeyFile, PublicKey: publicKey}, nil
}

// Options returns the nats.go connection options the resolved identity
// contributes (creds file or NKey seed signing).
func (a *NatsAuthenticationFiles) Options() []nats.Option {
	if a == nil {
		return nil
	}

	if a.CredentialsFile != nil {
		return []nats.Option{nats.UserCredentials(*a.CredentialsFile)}
	}

	if a.NKeyFile != nil {
		return []nats.Option{NatsNkeyOption(*a.NKeyFile)}
	}

	return nil
}

// NatsNkeyOption builds the nats.Nkey option from a seed file: the connection
// signs its server nonce with the seed's key pair.
func NatsNkeyOption(seedFile string) nats.Option {
	return func(o *nats.Options) error {
		seed, err := NkeySeed(seedFile)
		if err != nil {
			return err
		}

		pair, err := nkeys.FromSeed([]byte(seed))
		if err != nil {
			return err
		}

		publicKey, err := pair.PublicKey()
		if err != nil {
			return err
		}

		o.Nkey = publicKey
		o.SignatureCB = func(nonce []byte) ([]byte, error) {
			return pair.Sign(nonce)
		}

		return nil
	}
}

func natsAuthenticationResolvePrivateFile(value, optionName string) (string, error) {
	path, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("%s must identify a bounded existing NATS credentials file.", optionName)
	}
	if err := messagingRejectSymlinkPath(path); err != nil {
		return "", fmt.Errorf("%s must not contain symbolic links.", optionName)
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() < 1 || info.Size() > 16384 {
		return "", fmt.Errorf("%s must identify a bounded existing NATS credentials file.", optionName)
	}

	mode, err := MessagingUnixFileMode(path)
	if err != nil {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	if mode&(MessagingGroupAny|MessagingOtherAny) != 0 {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	return path, nil
}

func natsAuthenticationReadCredentialsSeed(path, optionPrefix string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s_CREDENTIALS_FILE is not a valid NATS user credentials file.", optionPrefix)
	}

	lines := strings.Split(string(data), "\n")
	begin := -1
	end := -1
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if begin < 0 && trimmed == "-----BEGIN USER NKEY SEED-----" {
			begin = index
			continue
		}

		if begin >= 0 && trimmed == "------END USER NKEY SEED------" {
			end = index
			break
		}
	}

	if begin < 0 || end <= begin+1 {
		return "", fmt.Errorf("%s_CREDENTIALS_FILE is not a valid NATS user credentials file.", optionPrefix)
	}

	for _, line := range lines[begin+1 : end] {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line), nil
		}
	}

	return "", fmt.Errorf("%s_CREDENTIALS_FILE contains no user NKey seed.", optionPrefix)
}
