"""The image's OCI consistent device path rule names each LUN as OCI does."""

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RULE = ROOT / "deploy/udev/65-terrascale-oci-device-paths.rules"
LINK = re.compile(r'^ENV\{ID_PATH\}=="pci-\*-scsi-0:0:0:(\d+)", SYMLINK\+="oracleoci/(oraclevd[a-z]+)"$')


def oci_device_name(lun: int) -> str:
    """OCI's device path for a paravirtualized LUN: a=1 (boot), b=2, ..., z=26, aa=27, ..., af=32."""
    letters = ""
    while lun:
        lun -= 1
        letters = chr(ord("a") + lun % 26) + letters
        lun //= 26
    return "oraclevd" + letters


class OCIDevicePathRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = [line for line in RULE.read_text(encoding="ascii").splitlines()
                      if line and not line.startswith("#")]

    def test_every_oci_device_path_names_its_paravirtualized_lun(self) -> None:
        links = {int(match[1]): match[2] for line in self.lines if (match := LINK.match(line))}
        self.assertEqual(links, {lun: oci_device_name(lun) for lun in range(1, 33)})
        # Oracle's documented pairs: the boot volume at LUN 1, the attach-time
        # example oraclevdb at LUN 2, oraclevdf at LUN 6, and the last name.
        for lun, name in ((1, "oraclevda"), (2, "oraclevdb"), (6, "oraclevdf"), (27, "oraclevdaa"), (32, "oraclevdaf")):
            self.assertEqual(links[lun], name)
        self.assertEqual(sum("SYMLINK" in line for line in self.lines), 32)

    def test_only_whole_oracle_block_volumes_on_a_pci_scsi_path_are_named(self) -> None:
        gate = self.lines[:self.lines.index('LABEL="terrascale_oci_block_volume"')]
        self.assertEqual(gate, [
            'ACTION=="remove", GOTO="terrascale_oci_device_paths_end"',
            'SUBSYSTEM!="block", GOTO="terrascale_oci_device_paths_end"',
            'ENV{DEVTYPE}!="disk", GOTO="terrascale_oci_device_paths_end"',
            'KERNEL!="sd*", GOTO="terrascale_oci_device_paths_end"',
            'SUBSYSTEMS=="scsi", ATTRS{vendor}=="ORACLE*", ATTRS{model}=="BlockVolume*", '
            'GOTO="terrascale_oci_block_volume"',
            'GOTO="terrascale_oci_device_paths_end"',
        ])
        body = self.lines[len(gate):]
        self.assertEqual(body[:2], ['LABEL="terrascale_oci_block_volume"', 'IMPORT{builtin}="path_id"'])
        self.assertEqual(body[-1], 'LABEL="terrascale_oci_device_paths_end"')
        self.assertTrue(all(LINK.match(line) for line in body[2:-1]))

    @unittest.skipUnless(shutil.which("udevadm"), "udevadm is not installed")
    def test_rule_file_parses_under_udev(self) -> None:
        result = subprocess.run(["udevadm", "verify", str(RULE)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
