// This file ports Security/InfisicalCli.cs.
package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	goruntime "runtime"
)

const infisicalForbiddenFileMode = 0o077
const infisicalPrivateFileMode = 0o600

// InfisicalCli ports the internal static InfisicalCli class; call it as
// security.InfisicalCli.Execute(...) to mirror the C# call site.
var InfisicalCli infisicalCli

type infisicalCli struct{}

// InfisicalCliAction is the closed CLI verb vocabulary.
type InfisicalCliAction int

const (
	InfisicalCliActionList InfisicalCliAction = iota
	InfisicalCliActionGet
	InfisicalCliActionCreate
	InfisicalCliActionUpdate
	InfisicalCliActionDelete
)

// InfisicalCliCommand is one parsed CLI command.
type InfisicalCliCommand struct {
	Action InfisicalCliAction
	Name   *string
	File   *string
}

// Execute runs one Infisical CLI command against the resolved configuration.
func (infisicalCli) Execute(
	ctx context.Context,
	arguments []string,
	environment func(string) (string, bool),
) (int, error) {
	command, err := InfisicalCli.Parse(arguments)
	if err != nil {
		return 0, err
	}
	configuration, resolveErr := InfisicalConfigurationResolveEnv(environment)
	if resolveErr != nil {
		return 0, resolveErr
	}
	if configuration == nil {
		return 0, &ArgumentError{Message: "Infisical is not configured."}
	}
	store := InfisicalSecretStoreCreate(configuration)
	defer store.Close()

	switch {
	case command.Action == InfisicalCliActionList && command.Name == nil && command.File == nil:
		secrets, listErr := store.List(ctx)
		if listErr != nil {
			return 0, listErr
		}
		for _, secret := range secrets {
			fmt.Printf("%s\t%s\tversion %d\n", secret.Path, secret.Name, secret.Version)
		}
	case command.Action == InfisicalCliActionGet && command.Name != nil && command.File != nil:
		secret, getErr := store.Get(ctx, *command.Name)
		if getErr != nil {
			return 0, getErr
		}
		if writeErr := infisicalWriteSecret(*command.File, secret.Value); writeErr != nil {
			return 0, writeErr
		}
		fullPath, _ := filepath.Abs(*command.File)
		fmt.Printf("wrote %s:%s@%d to %s\n", secret.Path, secret.Name, secret.Version, fullPath)
	case command.Action == InfisicalCliActionCreate && command.Name != nil && command.File != nil:
		value, readErr := infisicalReadSecret(*command.File)
		if readErr != nil {
			return 0, readErr
		}
		secret, createErr := store.Create(ctx, *command.Name, value)
		if createErr != nil {
			return 0, createErr
		}
		fmt.Printf("created %s:%s@%d\n", secret.Path, secret.Name, secret.Version)
	case command.Action == InfisicalCliActionUpdate && command.Name != nil && command.File != nil:
		value, readErr := infisicalReadSecret(*command.File)
		if readErr != nil {
			return 0, readErr
		}
		secret, updateErr := store.Update(ctx, *command.Name, value)
		if updateErr != nil {
			return 0, updateErr
		}
		fmt.Printf("updated %s:%s@%d\n", secret.Path, secret.Name, secret.Version)
	case command.Action == InfisicalCliActionDelete && command.Name != nil && command.File == nil:
		secret, deleteErr := store.Delete(ctx, *command.Name)
		if deleteErr != nil {
			return 0, deleteErr
		}
		fmt.Printf("deleted %s:%s@%d\n", secret.Path, secret.Name, secret.Version)
	default:
		return 0, &ArgumentOutOfRangeError{}
	}
	return 0, nil
}

// Parse validates the exact CLI shapes.
func (infisicalCli) Parse(arguments []string) (InfisicalCliCommand, error) {
	usage := infisicalUsage()
	if len(arguments) == 1 && arguments[0] == "list" {
		return InfisicalCliCommand{Action: InfisicalCliActionList}, nil
	}
	if len(arguments) == 4 && arguments[0] == "get" && arguments[2] == "--output" {
		name, err := infisicalRequireName(arguments[1], usage)
		if err != nil {
			return InfisicalCliCommand{}, err
		}
		file, err := infisicalRequireFile(arguments[3], usage)
		if err != nil {
			return InfisicalCliCommand{}, err
		}
		return InfisicalCliCommand{Action: InfisicalCliActionGet, Name: &name, File: &file}, nil
	}
	if len(arguments) == 4 && (arguments[0] == "create" || arguments[0] == "update") && arguments[2] == "--value-file" {
		name, err := infisicalRequireName(arguments[1], usage)
		if err != nil {
			return InfisicalCliCommand{}, err
		}
		file, err := infisicalRequireFile(arguments[3], usage)
		if err != nil {
			return InfisicalCliCommand{}, err
		}
		action := InfisicalCliActionCreate
		if arguments[0] == "update" {
			action = InfisicalCliActionUpdate
		}
		return InfisicalCliCommand{Action: action, Name: &name, File: &file}, nil
	}
	if len(arguments) == 4 && arguments[0] == "delete" && arguments[2] == "--confirm" && arguments[1] == arguments[3] {
		name, err := infisicalRequireName(arguments[1], usage)
		if err != nil {
			return InfisicalCliCommand{}, err
		}
		return InfisicalCliCommand{Action: InfisicalCliActionDelete, Name: &name}, nil
	}
	return InfisicalCliCommand{}, usage
}

func infisicalReadSecret(value string) (string, error) {
	path, err := infisicalRequirePrivateFile(value, true)
	if err != nil {
		return "", err
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return "", readErr
	}
	defer clearBytes(raw)
	if !utf8.Valid(raw) {
		return "", &InvalidDataError{Message: "The Infisical value file must contain UTF-8 text."}
	}
	return string(raw), nil
}

func infisicalWriteSecret(value string, secret string) error {
	if goruntime.GOOS != "linux" {
		return &PlatformNotSupportedError{
			Message: "Infisical secret files require Linux file permissions.",
		}
	}
	path, err := filepath.Abs(value)
	if err != nil {
		return &ArgumentError{Message: "The Infisical output directory does not exist."}
	}
	parent := filepath.Dir(path)
	if info, statErr := os.Stat(parent); statErr != nil || !info.IsDir() {
		return &ArgumentError{Message: "The Infisical output directory does not exist."}
	}
	if _, statErr := os.Lstat(path); statErr == nil {
		if _, privateErr := infisicalRequirePrivateFile(path, true); privateErr != nil {
			return privateErr
		}
	}
	random := make([]byte, 16)
	if _, randomErr := rand.Read(random); randomErr != nil {
		return randomErr
	}
	temporary := filepath.Join(parent,
		fmt.Sprintf(".%s.%s.tmp", filepath.Base(path), hex.EncodeToString(random)))
	payload := []byte(secret)
	defer func() {
		clearBytes(payload)
		os.Remove(temporary)
	}()
	file, createErr := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, infisicalPrivateFileMode)
	if createErr != nil {
		return createErr
	}
	if _, writeErr := file.Write(payload); writeErr != nil {
		file.Close()
		return writeErr
	}
	if syncErr := file.Sync(); syncErr != nil {
		file.Close()
		return syncErr
	}
	if closeErr := file.Close(); closeErr != nil {
		return closeErr
	}
	return os.Rename(temporary, path)
}

func infisicalRequirePrivateFile(value string, mustExist bool) (string, error) {
	if goruntime.GOOS != "linux" {
		return "", &PlatformNotSupportedError{
			Message: "Infisical secret files require Linux file permissions.",
		}
	}
	path, err := filepath.Abs(value)
	if err != nil {
		return "", &ArgumentError{
			Message: "The Infisical secret file must be bounded, regular, and owner-private.",
		}
	}
	if !mustExist {
		return path, nil
	}
	info, statErr := os.Stat(path)
	linkInfo, linkErr := os.Lstat(path)
	if statErr != nil || linkErr != nil || !info.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 ||
		info.Size() > 1024*1024 || unixMode(linkInfo)&infisicalForbiddenFileMode != 0 {
		return "", &ArgumentError{
			Message: "The Infisical secret file must be bounded, regular, and owner-private.",
		}
	}
	return path, nil
}

func infisicalRequireName(value string, usage *ArgumentError) (string, error) {
	if strings.TrimSpace(value) == "" || len(value) > 256 || strings.ContainsFunc(value, unicode.IsControl) {
		return "", usage
	}
	return value, nil
}

func infisicalRequireFile(value string, usage *ArgumentError) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", usage
	}
	return value, nil
}

func infisicalUsage() *ArgumentError {
	return &ArgumentError{
		Message: "Usage: infisical list | get <name> --output <file> | " +
			"create|update <name> --value-file <file> | delete <name> --confirm <name>.",
	}
}
