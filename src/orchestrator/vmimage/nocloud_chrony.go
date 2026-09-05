package vmimage

import "bytes"

// chronyd rejects a command socket directory that is accessible to other users.
// Keep group-readable traversal for chrony clients, with no world permissions.
func writeNoCloudChrony(output *bytes.Buffer, gateway string) {
	writeNoCloudLiteralFile(output, "/etc/chrony/chrony.conf", "root:root", "0644", "server "+gateway+" iburst minpoll 4 maxpoll 5\nmakestep 0.1 3\nrtcsync\ncmdport 0\nbindcmdaddress /run/chrony/chronyd.sock\n")
	writeNoCloudLiteralFile(output, "/etc/systemd/system/terrascale-vmqual-chrony.service", "root:root", "0644", `[Unit]
Description=TerraScale qualification guest clock synchronization
After=network-online.target
Wants=network-online.target
Conflicts=systemd-timesyncd.service

[Service]
Type=simple
ExecStart=/usr/sbin/chronyd -d -u root -f /etc/chrony/chrony.conf
RuntimeDirectory=chrony
RuntimeDirectoryMode=0750
StandardOutput=journal+console
StandardError=journal+console
Restart=on-failure

[Install]
WantedBy=multi-user.target
`)
}

func chronyBootstrapScript() string {
	return "/usr/bin/test -x /usr/sbin/chronyd\n" +
		"/usr/bin/test -x /usr/bin/chronyc\n" +
		"/usr/bin/systemctl disable --now systemd-timesyncd.service\n" +
		"/usr/bin/systemctl enable --now terrascale-vmqual-chrony.service\n" +
		"if ! /usr/bin/chronyc waitsync 30 0.1 0.0 2; then\n" +
		"  /usr/bin/timeout 5 /usr/bin/systemctl --no-pager --full status terrascale-vmqual-chrony.service || true\n" +
		"  /usr/bin/timeout 5 /usr/bin/journalctl --no-pager -n 30 -u terrascale-vmqual-chrony.service || true\n" +
		"  /usr/bin/timeout 5 /usr/bin/chronyc tracking || true\n" +
		"  /usr/bin/timeout 5 /usr/bin/chronyc sources || true\n" +
		"  exit 1\n" +
		"fi\n"
}
