package firecracker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type VM struct {
	Lab                          *Lab
	Name, IP, Tap, Image, Socket string
	Process                      *Process
	Boots                        int
}

func (v *VM) Boot() error {
	if v.Process != nil {
		return fmt.Errorf("%s is already running", v.Name)
	}
	v.Boots++
	_ = os.Remove(v.Socket)
	serial := filepath.Join(v.Lab.Logs, fmt.Sprintf("%s-boot-%d-serial.log", v.Name, v.Boots))
	output, e := os.OpenFile(serial, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if e != nil {
		return e
	}
	v.Process, e = Start([]string{v.Lab.Options.Firecracker, "--api-sock", v.Socket, "--log-path", filepath.Join(v.Lab.Logs, fmt.Sprintf("%s-boot-%d-vmm.log", v.Name, v.Boots))}, v.Lab.Options.SourceRoot, output)
	if e != nil {
		output.Close()
		return e
	}
	v.Process.Output = output
	deadline := v.Lab.Now().Add(20 * time.Second)
	for {
		if _, e = os.Stat(v.Socket); e == nil {
			break
		}
		done, e := v.Process.Exited()
		if e != nil {
			return e
		}
		if done {
			return fmt.Errorf("Firecracker %s exited before API socket; see %s", v.Name, serial)
		}
		if !v.Lab.Now().Before(deadline) {
			return fmt.Errorf("Firecracker %s API socket never appeared", v.Name)
		}
		v.Lab.Sleep(100 * time.Millisecond)
	}
	index := slices.Index(Guests, v.Name) + 1
	octet := v.Lab.Subnet.Addr().As4()[2]
	for _, request := range []struct {
		Path    string
		Payload Object
	}{{"/machine-config", Object{"vcpu_count": 1, "mem_size_mib": 512, "smt": false}}, {"/boot-source", Object{"kernel_image_path": v.Lab.Options.Kernel, "boot_args": "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw"}}, {"/drives/rootfs", Object{"drive_id": "rootfs", "path_on_host": v.Image, "is_root_device": true, "is_read_only": false}}, {"/network-interfaces/eth0", Object{"iface_id": "eth0", "host_dev_name": v.Tap, "guest_mac": fmt.Sprintf("02:fc:00:%02x:00:%02x", octet, index)}}, {"/actions", Object{"action_type": "InstanceStart"}}} {
		if e = UnixAPI(v.Lab.Ctx, v.Socket, request.Path, request.Payload); e != nil {
			return e
		}
	}
	v.Lab.Note("vm_boot", Object{"name": v.Name, "pid": v.Process.PID(), "serial": serial})
	return nil
}
func (v *VM) Stop() error {
	if v.Process == nil {
		return nil
	}
	if e := UnixAPI(v.Lab.Ctx, v.Socket, "/actions", Object{"action_type": "SendCtrlAltDel"}); e == nil {
		_, _ = v.Process.WaitUnreaped(25 * time.Second)
	}
	if e := v.Process.Stop(5*time.Second, false); e != nil {
		return e
	}
	v.Lab.Note("vm_stop", Object{"name": v.Name, "exit_code": v.Process.ExitCode})
	v.Process = nil
	return removeMissing(v.Socket)
}
func (v *VM) Crash() error {
	if v.Process == nil {
		return nil
	}
	if e := v.Process.Stop(5*time.Second, true); e != nil {
		return e
	}
	v.Lab.Note("vm_crash", Object{"name": v.Name, "pid": v.Process.PID(), "exit_code": v.Process.ExitCode})
	v.Process = nil
	return removeMissing(v.Socket)
}
func removeMissing(p string) error {
	e := os.Remove(p)
	if os.IsNotExist(e) {
		return nil
	}
	return e
}
func CleanupOwnedSockets(vms map[string]*VM, dir string) []string {
	for _, v := range vms {
		if v.Process != nil {
			return []string{fmt.Sprintf("keep Firecracker API sockets until %s is confirmed stopped", v.Name)}
		}
	}
	errs := []string{}
	for _, v := range vms {
		if e := removeMissing(v.Socket); e != nil {
			errs = append(errs, fmt.Sprintf("remove owned Firecracker API socket %s: %v", v.Socket, e))
		}
	}
	if len(errs) > 0 {
		return errs
	}
	if e := removeMissing(dir); e != nil {
		errs = append(errs, fmt.Sprintf("remove empty Firecracker API socket directory %s: %v", dir, e))
	}
	return errs
}
func (l *Lab) tlsFiles(name string, guest bool) Object {
	dir := l.Secrets
	if guest {
		dir = "/etc/ts-orch"
	}
	return Object{"ca_file": filepath.Join(dir, "nats-ca.pem"), "cert_file": filepath.Join(dir, "nats-"+name+".pem"), "key_file": filepath.Join(dir, "nats-"+name+".key")}
}
func (l *Lab) CreateTLSMaterial() error {
	caKey, caCert := filepath.Join(l.Secrets, "nats-ca.key"), filepath.Join(l.Secrets, "nats-ca.pem")
	for _, args := range [][]string{{"openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", caKey}, {"openssl", "req", "-new", "-x509", "-key", caKey, "-sha256", "-days", "2", "-subj", "/CN=ts-fc-" + l.Bridge, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", caCert}} {
		if _, e := l.cmd(args, CommandOptions{}); e != nil {
			return e
		}
	}
	if e := os.Chmod(caKey, 0o600); e != nil {
		return e
	}
	if e := os.Chmod(caCert, 0o600); e != nil {
		return e
	}
	fingerprints := Object{}
	seen := map[string]bool{}
	for i, name := range append(slices.Clone(Guests), "operator") {
		key, request, extension, certificate := filepath.Join(l.Secrets, "nats-"+name+".key"), filepath.Join(l.Secrets, "nats-"+name+".csr"), filepath.Join(l.Secrets, "nats-"+name+".ext"), filepath.Join(l.Secrets, "nats-"+name+".pem")
		san := "DNS:operator.lab.fc"
		if name != "operator" {
			san = "IP:" + l.Addresses[name] + ",DNS:" + name + ".lab.fc"
		}
		for _, args := range [][]string{{"openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key}, {"openssl", "req", "-new", "-key", key, "-out", request, "-subj", "/CN=" + name + ".lab.fc"}} {
			if _, e := l.cmd(args, CommandOptions{}); e != nil {
				return e
			}
		}
		if e := os.Chmod(key, 0o600); e != nil {
			return e
		}
		text := "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=" + san + "\n"
		if e := os.WriteFile(extension, []byte(text), 0o600); e != nil {
			return e
		}
		if _, e := l.cmd([]string{"openssl", "x509", "-req", "-in", request, "-CA", caCert, "-CAkey", caKey, "-set_serial", strconv.Itoa(i + 2), "-days", "2", "-sha256", "-extfile", extension, "-extensions", "leaf", "-out", certificate}, CommandOptions{}); e != nil {
			return e
		}
		if e := os.Chmod(certificate, 0o600); e != nil {
			return e
		}
		h, e := Digest(certificate)
		if e != nil {
			return e
		}
		if seen[h] {
			return errors.New("TLS leaf certificates were not distinct")
		}
		seen[h] = true
		fingerprints[name] = h
		_ = os.Remove(request)
		_ = os.Remove(extension)
	}
	if e := os.WriteFile(filepath.Join(l.Secrets, "route-password"), []byte(token(32)+"\n"), 0o600); e != nil {
		return e
	}
	ca, _ := Digest(caCert)
	l.Note("tls_material", Object{"minimum_version": "TLS1.3", "client_auth": "require_and_verify", "ca_sha256": ca, "certificate_sha256": fingerprints, "distinct_certificates": true})
	return nil
}
func (l *Lab) Identities() error {
	if _, e := l.cmd([]string{"ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", l.SSHKey}, CommandOptions{}); e != nil {
		return e
	}
	b, e := os.ReadFile(l.SSHKey + ".pub")
	if e != nil {
		return e
	}
	l.SSHPublic = strings.TrimSpace(string(b))
	for _, name := range []string{"controller", "operator", "host"} {
		r, e := l.cmd([]string{l.Binary, "identity-new", "--key", filepath.Join(l.Secrets, name+".key")}, CommandOptions{})
		if e != nil {
			return e
		}
		l.SigningPublic[name] = strings.TrimSpace(r.Stdout)
		if l.SigningPublic[name] == "" {
			return fmt.Errorf("identity-new returned no public key for %s", name)
		}
	}
	r, e := l.cmd([]string{l.JWTSetup, "--dir", l.Secrets, "--cell", "lab", "--brokers", strings.Join(Controllers, ","), "--host-node", "host-a"}, CommandOptions{})
	if e != nil {
		return e
	}
	v, e := decode(r.Stdout)
	if e != nil {
		return e
	}
	l.JWTManifest = object(v)
	users := object(l.JWTManifest["users"])
	if len(users) != 6 {
		return errors.New("JWT fixture returned incomplete public user identities")
	}
	for _, n := range []string{"c1", "c2", "c3", "operator", "host", "system"} {
		if _, ok := users[n]; !ok {
			return errors.New("JWT fixture returned incomplete public user identities")
		}
	}
	if e = l.CreateTLSMaterial(); e != nil {
		return e
	}
	l.Note("identities", Object{"operator_account": l.JWTManifest["operator_account"], "cell_account": l.JWTManifest["cell_account"]})
	return nil
}
func (l *Lab) Configs() error {
	signer := Object{"actor": "ops", "public_key": l.SigningPublic["operator"], "roles": []string{"terrabase"}, "environments": []string{"test"}, "can_register_hosts": true, "repositories": []string{str(l.Source["repository"])}}
	urls := []string{}
	for _, name := range Controllers {
		urls = append(urls, "tls://"+l.Addresses[name]+":4222")
	}
	for _, name := range Controllers {
		routes := []string{}
		for _, peer := range Controllers {
			if peer != name {
				routes = append(routes, "nats-route://"+l.Addresses[peer]+":6222")
			}
		}
		embedded := Object{"host": l.Addresses[name], "port": 4222, "route_host": l.Addresses[name], "route_port": 6222, "routes": routes, "store_dir": "/var/lib/ts-orch/nats", "store_max_bytes": 2 << 30, "tls": l.tlsFiles(name, true), "route_tls": l.tlsFiles(name, true), "route_user": "ts-fc-route", "route_password_file": "/etc/ts-orch/route-password", "operator_jwt_file": "/etc/ts-orch/operator.jwt", "system_jwt_file": "/etc/ts-orch/system.jwt", "cell_jwt_file": "/etc/ts-orch/cell.jwt", "system_credentials_file": "/etc/ts-orch/system.creds", "ticket_public_key_file": "/etc/ts-orch/broker-ticket.pub", "broker_ids": Controllers}
		config := Object{"nats": Object{"cell": "lab", "instance": name, "replicas": 3, "lab": false, "client_role": "controller", "tls": l.tlsFiles(name, true), "credentials_file": "/etc/ts-orch/" + name + ".creds", "embedded": embedded}, "controller": Object{"response_key_file": "/etc/ts-orch/controller.key", "broker_ticket_key_file": "/etc/ts-orch/broker-ticket.key", "artifact_store_max_bytes": 64 << 20, "trusted_signers": []Object{signer}, "workloads": Object{"terrabase": Object{"resources": Object{"cpu": 1, "memory_bytes": 67108864, "disk_bytes": 134217728}}}}}
		if e := writeJSON(filepath.Join(l.Secrets, name+".json"), config); e != nil {
			return e
		}
	}
	host := Object{"nats": Object{"cell": "lab", "instance": "host-a", "replicas": 3, "lab": false, "client_role": "host", "url": strings.Join(urls, ","), "tls": l.tlsFiles("host", true), "credentials_file": "/etc/ts-orch/host.creds"}, "host": Object{"node": "host-a", "environment": "test", "roles": []string{"terrabase"}, "session_trace": true, "workload_uid": 2000, "workload_gid": 2000, "identity_key_file": "/etc/ts-orch/host.key", "controller_public_key": l.SigningPublic["controller"], "install_root": "/var/lib/ts-orch-install", "state_root": "/var/lib/ts-orch/host", "poll_millis": 250}}
	if e := writeJSON(filepath.Join(l.Secrets, "host.json"), host); e != nil {
		return e
	}
	operator := Object{"nats": Object{"cell": "lab", "instance": "operator", "replicas": 3, "lab": false, "client_role": "operator", "url": strings.Join(urls, ","), "tls": l.tlsFiles("operator", false), "credentials_file": filepath.Join(l.Secrets, "operator.creds")}, "controller": Object{"trusted_signers": []Object{signer}}, "operator": Object{"actor": "ops", "signing_key_file": filepath.Join(l.Secrets, "operator.key"), "broker_ticket_public_key_file": filepath.Join(l.Secrets, "broker-ticket.pub")}}
	if e := writeJSON(l.OperatorConfig, operator); e != nil {
		return e
	}
	return writeJSON(filepath.Join(l.Secrets, "registration.json"), Object{"cell": "lab", "node": "host-a", "environment": "test", "roles": []string{"terrabase"}, "public_key": l.SigningPublic["host"], "generation": 1, "capacity": Object{"cpu": 2, "memory_bytes": 268435456, "disk_bytes": 536870912}})
}
func (l *Lab) Install(mount, source, destination, mode string) error {
	if !strings.HasPrefix(destination, "/") || slices.Contains(strings.Split(destination, "/"), "..") {
		return errors.New("invalid guest destination")
	}
	_, e := l.sudo("install", "-D", "-o", "root", "-g", "root", "-m", mode, source, filepath.Join(mount, strings.TrimPrefix(destination, "/")))
	return e
}
func (l *Lab) InstallText(mount, text, destination, mode string) error {
	f, e := os.CreateTemp(l.Stage, "guest-")
	if e != nil {
		return e
	}
	p := f.Name()
	defer os.Remove(p)
	if _, e = f.WriteString(text); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return l.Install(mount, p, destination, mode)
}
func (l *Lab) PrepareGuest(name string) error {
	image := filepath.Join(l.Images, name+".ext4")
	if _, e := l.cmd([]string{"cp", "--reflink=auto", "--sparse=always", l.Options.Rootfs, image}, CommandOptions{Timeout: 240 * time.Second}); e != nil {
		return e
	}
	if e := os.Truncate(image, 8<<30); e != nil {
		return e
	}
	r, e := l.cmd([]string{"e2fsck", "-f", "-y", image}, CommandOptions{Timeout: 240 * time.Second, AllowFailure: true})
	if e != nil {
		return e
	}
	if r.Code != 0 && r.Code != 1 {
		return fmt.Errorf("private ext4 check failed for %s: %s %s", name, tail(r.Stdout, 1000), tail(r.Stderr, 1000))
	}
	if _, e = l.cmd([]string{"resize2fs", image}, CommandOptions{Timeout: 240 * time.Second}); e != nil {
		return e
	}
	mount := filepath.Join(l.Root, "mount", name)
	if e = os.MkdirAll(mount, 0o700); e != nil {
		return e
	}
	l.Mounted = append(l.Mounted, mount)
	if _, e = l.sudo("mount", "-o", "loop", image, mount); e != nil {
		return e
	}
	stageErr := func() error {
		hostKey := filepath.Join(l.Secrets, "ssh-host-"+name)
		if _, e := l.cmd([]string{"ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey}, CommandOptions{}); e != nil {
			return e
		}
		b, e := os.ReadFile(hostKey + ".pub")
		if e != nil {
			return e
		}
		parts := strings.Fields(string(b))
		if len(parts) < 2 || parts[0] != "ssh-ed25519" {
			return errors.New("invalid generated SSH host key")
		}
		known, e := os.OpenFile(l.KnownHosts, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if e != nil {
			return e
		}
		_, e = fmt.Fprintf(known, "%s %s %s\n", l.Addresses[name], parts[0], parts[1])
		ce := known.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		for _, copy := range [][3]string{{l.Binary, "/usr/local/bin/terrascale-orchestrator", "0755"}, {l.ClockProbe, "/usr/local/bin/ts-orch-clockprobe", "0755"}, {hostKey, "/etc/ssh/ssh_host_ed25519_key", "0600"}, {hostKey + ".pub", "/etc/ssh/ssh_host_ed25519_key.pub", "0644"}} {
			if e = l.Install(mount, copy[0], copy[1], copy[2]); e != nil {
				return e
			}
		}
		role, key := "run", "controller"
		if name == "host" {
			role, key = "host", "host"
		}
		for _, copy := range [][3]string{{l.SSHPublic + "\n", "/root/.ssh/authorized_keys", "0600"}, {"", "/etc/cloud/cloud-init.disabled", "0644"}, {"PermitRootLogin prohibit-password\nPasswordAuthentication no\n", "/etc/ssh/sshd_config.d/99-ts-orch-fc.conf", "0644"}, {"[Match]\nName=e*\n\n[Network]\nAddress=" + l.Addresses[name] + "/24\n", "/etc/systemd/network/80-ts-orch-fc.network", "0644"}, {"[Time]\nNTP=" + l.gateway() + "\nFallbackNTP=\nRootDistanceMaxSec=1\n", "/etc/systemd/timesyncd.conf.d/ts-orch-fc.conf", "0644"}, {GuestUnit(name, role), "/etc/systemd/system/ts-orch.service", "0644"}} {
			if e = l.InstallText(mount, copy[0], copy[1], copy[2]); e != nil {
				return e
			}
		}
		for _, copy := range [][2]string{{name + ".json", "config.json"}, {name + ".creds", name + ".creds"}, {"nats-ca.pem", "nats-ca.pem"}, {"nats-" + name + ".pem", "nats-" + name + ".pem"}, {"nats-" + name + ".key", "nats-" + name + ".key"}, {key + ".key", key + ".key"}} {
			if e = l.Install(mount, filepath.Join(l.Secrets, copy[0]), "/etc/ts-orch/"+copy[1], "0600"); e != nil {
				return e
			}
		}
		if name != "host" {
			for _, file := range []string{"route-password", "operator.jwt", "system.jwt", "cell.jwt", "system.creds", "broker-ticket.key", "broker-ticket.pub"} {
				if e = l.Install(mount, filepath.Join(l.Secrets, file), "/etc/ts-orch/"+file, "0600"); e != nil {
					return e
				}
			}
		}
		for _, unit := range []string{"systemd-networkd.service", "ssh.service", "systemd-timesyncd.service", "ts-orch.service"} {
			if _, e = l.sudo("systemctl", "--root="+mount, "enable", unit); e != nil {
				return e
			}
		}
		return nil
	}()
	if pendingErrors := quiescePendingCommands(&l.PendingCommands); len(pendingErrors) > 0 {
		return errors.Join(stageErr, fmt.Errorf("preserve guest image and mount %s: %s", mount, strings.Join(pendingErrors, "; ")))
	}
	_, unmountErr := l.sudo("umount", mount)
	if unmountErr == nil {
		l.Mounted = slices.DeleteFunc(l.Mounted, func(p string) bool { return p == mount })
	}
	if e = errors.Join(stageErr, unmountErr); e != nil {
		return e
	}
	socket, e := SocketPath(l.SocketDir, name)
	if e != nil {
		return e
	}
	l.VMs[name] = &VM{Lab: l, Name: name, IP: l.Addresses[name], Tap: l.Taps[name], Image: image, Socket: socket}
	l.Note("guest_prepared", Object{"name": name, "image": image, "virtual_disk_bytes": 8 << 30})
	return nil
}
func (l *Lab) Artifact(version string) (Object, error) {
	p := filepath.Join(l.Stage, "workload-"+version+".sh")
	text := "#!/bin/sh\nset -eu\nprintf '%s\\n' " + quote(version) + " > /run/ts-orch-workload/marker\nprintf '%s\\n' \"$$\" > /run/ts-orch-workload/pid\nwhile :; do sleep 1; done\n"
	if e := os.WriteFile(p, []byte(text), 0o755); e != nil {
		return nil, e
	}
	h, e := Digest(p)
	if e != nil {
		return nil, e
	}
	l.Source["treeDigest"] = h
	v, e := l.Operator("artifact-push", 35*time.Second, false, "", "--file", p, "--repository", str(l.Source["repository"]), "--commit", str(l.Source["commit"]), "--tree-digest", h, "--role", "terrabase", "--environment", "test")
	if e != nil {
		return nil, e
	}
	record := object(v)
	if record["digest"] != h {
		return nil, fmt.Errorf("artifact %s did not return its exact content digest", version)
	}
	return record, nil
}
