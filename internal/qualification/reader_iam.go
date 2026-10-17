package qualification

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

var readerID = regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)

func ValidReaderIAMIDs(group, policy string) bool {
	return readerID.MatchString(group) && strings.HasPrefix(group, "ocid1.dynamicgroup.") && readerID.MatchString(policy) && strings.HasPrefix(policy, "ocid1.policy.")
}

// ReaderMatchingRule admits only the four original-signer bound instances.
func ReaderMatchingRule(ids []string) string {
	if len(ids) != 4 {
		return ""
	}
	ids = slices.Sorted(slices.Values(ids))
	parts := make([]string, len(ids))
	for i, id := range ids {
		if !readerID.MatchString(id) || !strings.HasPrefix(id, "ocid1.instance.") || i > 0 && id == ids[i-1] {
			return ""
		}
		parts[i] = "instance.id = '" + id + "'"
	}
	return "ANY {" + strings.Join(parts, ", ") + "}"
}

// ReaderStatements permits only the actual local-instance/image scenario and
// the live placement, boot geometry and namespace checks needed to admit it.
func ReaderStatements(group, compartment string, expires time.Time) []string {
	statement := func(resource, location, conditions string, operations ...string) string {
		parts := make([]string, len(operations))
		for i, op := range operations {
			parts[i] = "request.operation='" + op + "'"
		}
		return fmt.Sprintf("Allow dynamic-group id %s to %s in %s where all {request.utc-timestamp < '%s', %sany {%s}}", group, resource, location, expires.UTC().Format(time.RFC3339), conditions, strings.Join(parts, ", "))
	}
	location := "compartment id " + compartment
	return []string{
		statement("read instances", location, "", "GetInstance", "ListVnicAttachments"),
		statement("read instance-images", location, "", "GetImage"),
		statement("read volumes", location, "", "GetBootVolume"),
		statement("inspect volume-attachments", location, "", "ListBootVolumeAttachments"),
		statement("read virtual-network-family", location, "", "GetVnic", "GetSubnet"),
		statement("read objectstorage-namespaces", "tenancy", "", "GetNamespace"),
	}
}
