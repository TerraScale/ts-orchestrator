// This file ports Runtime/HostRuntimeCli.cs.
package runtime

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// HostRuntimeCli ports the internal static HostRuntimeCli class; call it as
// runtime.HostRuntimeCli.Execute(arguments) to mirror the C# call site.
var HostRuntimeCli hostRuntimeCli

type hostRuntimeCli struct{}

// Execute prints one canonical plan document and returns the exit code.
func (hostRuntimeCli) Execute(arguments []string) int {
	plan, err := HostRuntimeCli.ParsePlan(arguments)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	var buffer strings.Builder
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan); err != nil {
		fmt.Println(err.Error())
		return 1
	}
	fmt.Print(buffer.String())
	return 0
}

// ParsePlan parses the exact `runtime plan` option vocabulary.
func (hostRuntimeCli) ParsePlan(arguments []string) (HostRuntimePlan, error) {
	if len(arguments) == 0 || arguments[0] != "plan" {
		return HostRuntimePlan{}, &errs.Argument{Message: "Unknown runtime command. Use 'runtime plan'."}
	}
	values, err := parseRuntimePlanValues(arguments[1:])
	if err != nil {
		return HostRuntimePlan{}, err
	}
	roleText, err := requiredRuntimePlanValue(values, "--role")
	if err != nil {
		return HostRuntimePlan{}, err
	}
	role, err := HostRuntimeCli.ParseRole(roleText)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	descriptor, err := AdmittedRoleCatalog.Get(role)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	driver := descriptor.DefaultDriver
	if driverValue, present := values["--driver"]; present {
		driver, err = parseRuntimeDriver(driverValue)
		if err != nil {
			return HostRuntimePlan{}, err
		}
	}
	architecture := HostArchitectureArm64
	if architectureValue, present := values["--architecture"]; present {
		architecture, err = parseHostArchitecture(architectureValue)
		if err != nil {
			return HostRuntimePlan{}, err
		}
	}
	defaults, err := RuntimeResourceLimitPolicy.For(role, nil)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	memoryMaxBytes, err := runtimePlanLong(values, "--memory-max-bytes", defaults.MemoryMaxBytes)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	tasksMax, err := runtimePlanInteger(values, "--tasks-max", defaults.TasksMax)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	cpuQuotaPercent, err := runtimePlanInteger(values, "--cpu-quota-percent", defaults.CpuQuotaPercent)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	cpuWeight, err := runtimePlanInteger(values, "--cpu-weight", defaults.CpuWeight)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	ioWeight, err := runtimePlanInteger(values, "--io-weight", defaults.IoWeight)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	nice, err := runtimePlanInteger(values, "--nice", defaults.Nice)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	resources := RuntimeResourceLimits{
		MemoryMaxBytes:  memoryMaxBytes,
		TasksMax:        tasksMax,
		CpuQuotaPercent: cpuQuotaPercent,
		CpuWeight:       cpuWeight,
		IoWeight:        ioWeight,
		Nice:            nice,
	}
	allocationText, err := requiredRuntimePlanValue(values, "--allocation")
	if err != nil {
		return HostRuntimePlan{}, err
	}
	allocation, err := NewRuntimeAllocationId(allocationText)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	digestText, err := requiredRuntimePlanValue(values, "--digest")
	if err != nil {
		return HostRuntimePlan{}, err
	}
	digest, err := NewArtifactDigest(digestText)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	return NewHostRuntimePlan(role, driver, allocation, digest, architecture, &resources)
}

// ParseRole parses the closed role vocabulary.
func (hostRuntimeCli) ParseRole(value string) (AdmittedRole, error) {
	switch value {
	case "customer-dashboard":
		return AdmittedRoleCustomerDashboard, nil
	case "terrabase-member":
		return AdmittedRoleTerraBaseMember, nil
	case "orchestrator":
		return AdmittedRoleOrchestrator, nil
	case "control-nats-server":
		return AdmittedRoleControlNatsServer, nil
	case "product-nats-server":
		return AdmittedRoleProductNatsServer, nil
	case "grafana":
		return AdmittedRoleGrafana, nil
	case "metrics-store":
		return AdmittedRoleMetricsStore, nil
	case "loki":
		return AdmittedRoleLoki, nil
	case "tempo":
		return AdmittedRoleTempo, nil
	case "alertmanager":
		return AdmittedRoleAlertmanager, nil
	case "otlp-ingest":
		return AdmittedRoleOtlpIngest, nil
	case "synthetic-check":
		return AdmittedRoleSyntheticCheck, nil
	case "regional-telemetry-agent":
		return AdmittedRoleRegionalTelemetryAgent, nil
	case "vpn-coordination-relay":
		return AdmittedRoleVpnCoordinationRelay, nil
	case "route-policy-controller":
		return AdmittedRoleRoutePolicyController, nil
	case "ci-runner":
		return AdmittedRoleCiRunner, nil
	default:
		return AdmittedRole(0), &errs.Argument{
			Message: fmt.Sprintf("Unknown or unadmitted role '%s'.", value),
		}
	}
}

func parseRuntimeDriver(value string) (RuntimeDriver, error) {
	switch value {
	case "systemd":
		return RuntimeDriverNativeSystemd, nil
	case "oci":
		return RuntimeDriverOciContainer, nil
	default:
		return RuntimeDriverNativeSystemd, &errs.Argument{
			Message: "Runtime driver must be 'systemd' or 'oci'.",
		}
	}
}

func parseHostArchitecture(value string) (HostArchitecture, error) {
	switch value {
	case "arm64":
		return HostArchitectureArm64, nil
	case "x64":
		return HostArchitectureX64, nil
	default:
		return HostArchitectureArm64, &errs.Argument{
			Message: "Architecture must be 'arm64' or 'x64'.",
		}
	}
}

func parseRuntimePlanValues(arguments []string) (map[string]string, error) {
	values := make(map[string]string)
	for index := 0; index < len(arguments); index += 2 {
		if index+1 >= len(arguments) || !strings.HasPrefix(arguments[index], "--") {
			return nil, &errs.Argument{
				Message: "Runtime plan options must be '--name value' pairs.",
			}
		}
		if _, duplicate := values[arguments[index]]; duplicate {
			return nil, &errs.Argument{
				Message: fmt.Sprintf("Duplicate runtime option '%s'.", arguments[index]),
			}
		}
		values[arguments[index]] = arguments[index+1]
	}
	allowed := map[string]bool{
		"--role": true, "--driver": true, "--allocation": true, "--digest": true,
		"--architecture": true, "--memory-max-bytes": true, "--tasks-max": true,
		"--cpu-quota-percent": true, "--cpu-weight": true, "--io-weight": true,
		"--nice": true,
	}
	// C# reports the first unknown key in dictionary insertion order; Go maps
	// are unordered, so report the first unknown key in argument order instead.
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "--") && !allowed[argument] {
			return nil, &errs.Argument{
				Message: fmt.Sprintf("Unknown runtime option '%s'.", argument),
			}
		}
	}
	return values, nil
}

func requiredRuntimePlanValue(values map[string]string, key string) (string, error) {
	if value, present := values[key]; present && strings.TrimSpace(value) != "" {
		return value, nil
	}
	return "", &errs.Argument{
		Message: fmt.Sprintf("Runtime plan requires %s.", key),
	}
}

func runtimePlanInteger(values map[string]string, key string, fallback int) (int, error) {
	value, present := values[key]
	if !present {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, &errs.Argument{
			Message: fmt.Sprintf("Runtime option %s must be an integer.", key),
		}
	}
	return int(parsed), nil
}

func runtimePlanLong(values map[string]string, key string, fallback int64) (int64, error) {
	value, present := values[key]
	if !present {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, &errs.Argument{
			Message: fmt.Sprintf("Runtime option %s must be an integer.", key),
		}
	}
	return parsed, nil
}
