package vmqual

// Host tools may invoke other system utilities. Use only
// system-managed binary directories, including the activated NixOS system;
// never inherit user PATH entries into privileged qualification commands.
func hostToolEnvironment() []string {
	return []string{"LANG=C", "LC_ALL=C", "PATH=/run/current-system/sw/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
}
