package terrabase

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

const cliUsage = "Usage: ts-orch terrabase member-ca --cell CELL --out DIR\n" +
	"       ts-orch terrabase data-volume --plan FILE --member NAME (--instance OCID | --grow-gb N) [--compartment OCID] [--apply]\n" +
	"       ts-orch terrabase restore-volume --plan FILE --member NAME --scratch-instance OCID [--backup OCID] [--compartment OCID] [--apply]\n" +
	"       ts-orch terrabase restore-check --plan FILE --binary FILE --organization ORG --database DBID --document PATH --scratch-instance OCID --restored-volume OCID [--compartment OCID] [--ready-path PATH] [--wait D] [--apply]\n\n" +
	"  member-ca       Create a cell's TerraBase member CA: DIR/member-ca.pem and the owner-only DIR/member-ca.key\n" +
	"  data-volume     Print, or with --apply create and attach (or grow) a member's OCI data volume NAME-data\n" +
	"  restore-volume  Print, or with --apply restore a backup of NAME-data into a new volume on a scratch instance\n" +
	"  restore-check   On the scratch host: print, or with --apply start TerraBase on the restored volume and read a document\n"

// Run dispatches the TerraBase commands. member-ca is local; the volume
// commands read or change OCI, and restore-check the local host, only with
// --apply.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "data-volume":
			return runDataVolume(ctx, args[1:], output)
		case "restore-volume":
			return runRestoreVolume(ctx, args[1:], output)
		case "restore-check":
			return runRestoreCheck(ctx, args[1:], output)
		case "__restore-check":
			return runIsolatedRestoreCheck(ctx, os.Stdin, output)
		}
	}
	if len(args) == 0 || args[0] != "member-ca" {
		_, err := io.WriteString(output, cliUsage)
		if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
			return err
		}
		return fmt.Errorf("unknown terrabase command %q", args[0])
	}
	flags := flag.NewFlagSet("terrabase member-ca", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cell := flags.String("cell", "", "cell name, for example gru-1")
	out := flags.String("out", "", "new directory for the CA files")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *cell == "" || *out == "" {
		return errors.New("member-ca requires --cell and --out")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	certificate, key, err := NewCA(*cell, time.Now())
	if err != nil {
		return err
	}
	// A new directory: an existing CA is never overwritten.
	if err := os.Mkdir(*out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "member-ca.key"), key, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "member-ca.pem"), certificate, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "{\"certificate\":%q,\"key\":%q}\n",
		filepath.Join(*out, "member-ca.pem"), filepath.Join(*out, "member-ca.key"))
	return err
}

// cellPlan is the part of a cell plan (deploy/oci-region/plan.json) that
// sizes and places member data volumes. Member slots map to member names
// in plan order: the first member-* host is <cell>-db-1.
type cellPlan struct {
	Cell               string `json:"cell"`
	AvailabilityDomain string `json:"availability_domain"`
	VPUsPerGB          uint32 `json:"volume_vpus_per_gb"`
	Hosts              []struct {
		Slot   string `json:"slot"`
		DataGB int64  `json:"data_gb"`
	} `json:"hosts"`
	ResourceIDs struct {
		WorkloadCompartment string            `json:"workload_compartment"`
		DataVolumes         map[string]string `json:"data_volumes"`
	} `json:"resource_ids"`
}

// dataVolumeRequest is one resolved data-volume command; it is printed as
// is without --apply.
type dataVolumeRequest struct {
	Step               string `json:"step"`
	Apply              bool   `json:"apply"`
	Member             string `json:"member"`
	Volume             string `json:"volume"`
	SizeGB             int64  `json:"size_gb"`
	GrowGB             int64  `json:"grow_gb,omitzero"`
	RecordedVolume     string `json:"recorded_volume,omitempty"`
	Backup             string `json:"backup,omitempty"`
	Instance           string `json:"instance,omitempty"`
	Device             string `json:"device"`
	Compartment        string `json:"compartment"`
	AvailabilityDomain string `json:"availability_domain"`
	VPUsPerGB          uint32 `json:"vpus_per_gb"`
	region             oci.Region
}

func runDataVolume(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("terrabase data-volume", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "cell plan, for example deploy/oci-region/plan.json")
	member := flags.String("member", "", "member name, for example gru-1-db-1")
	instance := flags.String("instance", "", "OCID of the running instance named --member")
	grow := flags.Int64("grow-gb", 0, "grow the existing volume to this size instead of attaching")
	compartment := flags.String("compartment", "", "workload compartment OCID; defaults to the plan's resource_ids.workload_compartment")
	apply := flags.Bool("apply", false, "perform the OCI calls; without it only print the request")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *planPath == "" || *member == "" || (*instance == "") == (*grow == 0) {
		return errors.New("data-volume requires --plan, --member and exactly one of --instance or --grow-gb")
	}
	wire, err := os.ReadFile(*planPath)
	if err != nil {
		return err
	}
	request, err := resolveDataVolume(wire, *member, *instance, *compartment, *grow, *apply)
	if err != nil {
		return err
	}
	if !request.Apply {
		wire, err := json.Marshal(request)
		if err == nil {
			_, err = fmt.Fprintf(output, "%s\n", wire)
		}
		return err
	}
	volumes, err := oci.NewOperatorMemberVolumes(oci.MemberVolumeConfig{Region: request.region,
		CompartmentID: request.Compartment, AvailabilityDomain: request.AvailabilityDomain, VPUsPerGB: request.VPUsPerGB})
	if err != nil {
		return err
	}
	if request.GrowGB != 0 {
		grown, err := volumes.Resize(ctx, request.Member, request.RecordedVolume, request.GrowGB)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "{\"step\":\"grown\",\"volume\":%q,\"volume_id\":%q,\"size_gb\":%d}\n", request.Volume, grown.ID, grown.SizeGB)
		return err
	}
	attachment, err := volumes.Ensure(ctx, oci.MemberVolumeRequest{Member: request.Member, InstanceID: request.Instance,
		SizeGB: request.SizeGB, VolumeID: request.RecordedVolume})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "{\"step\":\"attached\",\"volume\":%q,\"volume_id\":%q,\"attachment_id\":%q,\"instance\":%q,\"device\":%q}\n",
		request.Volume, attachment.VolumeID, attachment.ID, attachment.InstanceID, attachment.Device)
	return err
}

func resolveDataVolume(wire []byte, member, instance, compartment string, grow int64, apply bool) (dataVolumeRequest, error) {
	var plan cellPlan
	if err := json.Unmarshal(wire, &plan); err != nil {
		return dataVolumeRequest{}, fmt.Errorf("decode cell plan: %w", err)
	}
	cell := naming.RegionCell(plan.Cell)
	sizeGB, index, recorded := int64(0), 0, ""
	for _, host := range plan.Hosts {
		if !strings.HasPrefix(host.Slot, "member-") {
			continue
		}
		index++
		if name, err := cell.Server(naming.Member, index); err == nil && name == member {
			// A recorded volume is never recreated: see oci.MemberVolumeRequest.
			sizeGB, recorded = host.DataGB, plan.ResourceIDs.DataVolumes[host.Slot]
		}
	}
	if sizeGB == 0 {
		return dataVolumeRequest{}, fmt.Errorf("member %s is not a member host of the plan's cell with data_gb", member)
	}
	volume, err := naming.Data(member)
	if err != nil {
		return dataVolumeRequest{}, err
	}
	if compartment == "" {
		compartment = plan.ResourceIDs.WorkloadCompartment
	}
	if compartment == "" || plan.AvailabilityDomain == "" {
		return dataVolumeRequest{}, errors.New("data-volume needs the plan's availability_domain and a workload compartment (--compartment until the plan records it)")
	}
	step := "attach"
	if grow != 0 {
		step = "grow"
	}
	return dataVolumeRequest{Step: step, Apply: apply, Member: member, Volume: volume, SizeGB: sizeGB, GrowGB: grow, RecordedVolume: recorded,
		Instance: instance, Device: oci.MemberVolumeDevice, Compartment: compartment,
		AvailabilityDomain: plan.AvailabilityDomain, VPUsPerGB: plan.VPUsPerGB, region: oci.Region(plan.Cell)}, nil
}

func runRestoreVolume(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("terrabase restore-volume", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "cell plan, for example deploy/oci-region/plan.json")
	member := flags.String("member", "", "member whose backup is restored, for example gru-1-db-1")
	scratch := flags.String("scratch-instance", "", "OCID of the running scratch instance, not a member host")
	backup := flags.String("backup", "", "backup OCID; defaults to the newest AVAILABLE backup of the member's volume")
	compartment := flags.String("compartment", "", "workload compartment OCID; defaults to the plan's resource_ids.workload_compartment")
	apply := flags.Bool("apply", false, "perform the OCI calls; without it only print the request")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *planPath == "" || *member == "" || *scratch == "" {
		return errors.New("restore-volume requires --plan, --member and --scratch-instance")
	}
	wire, err := os.ReadFile(*planPath)
	if err != nil {
		return err
	}
	request, err := resolveDataVolume(wire, *member, *scratch, *compartment, 0, *apply)
	if err != nil {
		return err
	}
	// Print what --apply creates: the restored copy, at the restore device.
	request.Step, request.Backup = "restore", *backup
	request.Volume, request.Device = "restore-"+request.Volume, oci.RestoreVolumeDevice
	if !request.Apply {
		wire, err := json.Marshal(request)
		if err == nil {
			_, err = fmt.Fprintf(output, "%s\n", wire)
		}
		return err
	}
	volumes, err := oci.NewOperatorMemberVolumes(oci.MemberVolumeConfig{Region: request.region,
		CompartmentID: request.Compartment, AvailabilityDomain: request.AvailabilityDomain, VPUsPerGB: request.VPUsPerGB})
	if err != nil {
		return err
	}
	restored, err := volumes.Restore(ctx, oci.RestoreRequest{Member: request.Member, BackupID: request.Backup,
		ScratchInstanceID: request.Instance, SourceVolumeID: request.RecordedVolume})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "{\"step\":\"restored\",\"backup_id\":%q,\"volume_id\":%q,\"attachment_id\":%q,\"instance\":%q,\"device\":%q}\n",
		restored.BackupID, restored.VolumeID, restored.ID, restored.InstanceID, restored.Device)
	return err
}
