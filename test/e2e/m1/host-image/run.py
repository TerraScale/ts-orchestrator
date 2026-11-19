import argparse
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('arch', choices=('amd64', 'arm64'))
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent
    accel = 'kvm' if os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg'
    print(f'host-image {args.arch}: accelerator={accel}', flush=True)
    environment = dict(os.environ, LIBGUESTFS_BACKEND='direct')
    with tempfile.TemporaryDirectory(prefix='host-image-') as temporary:
        work = Path(temporary)
        harness = work / 'host-image'
        shutil.copytree(here, harness)
        prepared = work / 'prepared.qcow2'
        run('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), str(prepared))
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
            '-keyout', str(harness / 'localhost.key'), '-out', str(harness / 'localhost.crt'),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(work / 'ssh-key'))
        shutil.copyfile(work / 'ssh-key.pub', harness / 'ssh-key.pub')
        serial = '1234567890abcdef1234567890abcdef'
        rule = work / '99-host-image.rules'
        rule.write_text(
            'SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ATTRS{model}=="BlockVolume*", '
            f'ENV{{ID_SERIAL_SHORT}}="{serial}", ENV{{ID_WWN}}="0x{serial}", '
            'SYMLINK+="oracleoci/oraclevdb"\n'
        )
        dependency = work / 'metadata.conf'
        dependency.write_text('[Unit]\nRequires=host-image-metadata.service\nAfter=host-image-metadata.service\n')
        run('virt-customize', '--no-network', '-a', str(prepared), '--copy-in', f'{harness}:/opt',
            '--upload', f'{rule}:/etc/udev/rules.d/99-host-image.rules',
            '--upload', f'{harness}/metadata.service:/etc/systemd/system/host-image-metadata.service',
            '--upload', f'{harness}/check.service:/etc/systemd/system/host-image-check.service',
            '--mkdir', '/etc/systemd/system/ts-node-init.service.d',
            '--upload', f'{dependency}:/etc/systemd/system/ts-node-init.service.d/host-image.conf',
            '--upload', f'{harness}/localhost.crt:/usr/local/share/ca-certificates/host-image.crt',
            '--run-command', 'update-ca-certificates',
            '--run-command', 'cp /usr/local/bin/terrascale-orchestrator /opt/host-image/release && '
            "printf '\\nC2t launch release\\n' >> /opt/host-image/release && "
            "sha256sum /opt/host-image/release | cut -d' ' -f1 > /opt/host-image/launch.sha256",
            '--run-command', 'systemctl enable host-image-check.service',
            '--run-command', 'truncate -s 0 /etc/machine-id && '
            'rm -f /var/lib/systemd/random-seed /var/lib/urandom/random-seed', env=environment)
        summary = [f'### Host image {args.arch} ({accel})', '',
                   '| Case | Boot to ts-orch active | Observed at | VM wall time |',
                   '| --- | ---: | --- | ---: |']
        first_root = first_data = None
        for case in ('first-boot', 'reboot', 'launch-release', 'late-bind', 'wrong-sha256'):
            if case == 'reboot':
                root, data = first_root, first_data
            else:
                root, data = work / f'{case}.qcow2', work / f'{case}-data.raw'
                run('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(prepared), str(root))
                run('truncate', '-s', '2G', str(data))
                if case == 'first-boot':
                    first_root, first_data = root, data
            marker = work / 'case'
            marker.write_text(case + '\n')
            run('guestfish', '--rw', '-a', str(root), '-i', 'upload', str(marker), '/etc/host-image-case',
                env=environment)
            command = [f'qemu-system-{"x86_64" if args.arch == "amd64" else "aarch64"}',
                       '-accel', accel, '-m', '2048', '-smp', '2', '-nographic', '-monitor', 'none',
                       '-no-reboot', '-nic', 'user,model=virtio-net-pci',
                       '-drive', f'file={root},format=qcow2,if=none,id=root',
                       '-device', 'virtio-blk-pci,drive=root,bootindex=1',
                       '-device', 'virtio-scsi-pci,id=scsi',
                       '-drive', f'file={data},format=raw,if=none,id=data',
                       '-device', f'scsi-hd,drive=data,bus=scsi.0,product=BlockVolume,serial={serial},device_id=c2t']
            if args.arch == 'arm64':
                command += ['-machine', 'virt', '-cpu', 'host' if accel == 'kvm' else 'max',
                            '-bios', '/usr/share/AAVMF/AAVMF_CODE.fd']
            else:
                command += ['-machine', 'q35']
            log = output / f'{case}.log'
            began = time.monotonic()
            try:
                with log.open('w') as stream:
                    run(*command, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
                content = log.read_text(errors='replace')
                if f'host-image {case}: PASS' not in content or f'host-image {case}: FAIL' in content:
                    raise RuntimeError(f'{case}: guest assertions failed')
            except BaseException:
                print(log.read_text(errors='replace')[-24000:], flush=True)
                raise
            elapsed = time.monotonic() - began
            print(f'host-image {case}: PASS ({elapsed:.2f}s VM wall time)', flush=True)
            for line in content.splitlines():
                if re.search(r'BOOT-TIME|UUID=|replaced the image|nothing installed|ActiveEnterTimestamp|data volume', line):
                    print(line, flush=True)
            timing = re.search(rf'BOOT-TIME {case} (\d+) us; (\S+)', content)
            if case != 'wrong-sha256' and (not timing or int(timing[1]) <= 0):
                raise RuntimeError(f'{case}: missing boot-to-active timestamp')
            active, timestamp = (f'{int(timing[1]) / 1e6:.3f}s', timing[2]) if timing else ('rejected', 'n/a')
            summary.append(f'| {case}: PASS | {active} | {timestamp} | {elapsed:.2f}s |')
            (output / 'summary.md').write_text('\n'.join(summary) + '\n')
            if summary_path := os.environ.get('GITHUB_STEP_SUMMARY'):
                Path(summary_path).write_text('\n'.join(summary) + '\n')


if __name__ == '__main__':
    main()
