#!/usr/bin/env python3
"""Expose the TerraBase HTTPS API of one cell through a public OCI Network Load Balancer.

    public-api.py --plan PLAN.json --members 10.251.0.21,10.251.0.22 [--client-port 9465]

Idempotent find-or-create by display name, all free-tier resources:
  * an internet gateway and a public subnet with its own route table and
    security list (TCP 443 in, the member client port out to the private
    subnet only),
  * a public Network Load Balancer passing TLS on 443 through to each
    member's client port (TerraBase terminates TLS and authenticates),
  * one workload-NSG rule admitting the client port from the public subnet.
The members stay in the private subnet without public addresses. Prints
the load balancer's public IP.
"""

import argparse
import ipaddress
import json
import pathlib
import subprocess
import sys
import time

PREFIX = "terrascale-gru-public"


def oci(*args: str) -> dict:
    result = subprocess.run(["oci", *args, "--output", "json"], capture_output=True, text=True, check=False)
    if result.returncode:
        raise SystemExit(f"oci {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def named(rows: list[dict], name: str) -> dict | None:
    live = [row for row in rows if row.get("display-name") == name and
            row.get("lifecycle-state") not in ("TERMINATED", "TERMINATING", "DELETED", "DELETING")]
    return live[0] if live else None


def wait_state(get: list[str], state: str) -> dict:
    for _ in range(90):
        row = oci(*get)["data"]
        if row["lifecycle-state"] == state:
            return row
        time.sleep(10)
    raise SystemExit(f"{get[:3]} did not reach {state}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", type=pathlib.Path, required=True)
    parser.add_argument("--members", required=True, help="comma-separated member private IPs")
    parser.add_argument("--client-port", type=int, default=9465)
    parser.add_argument("--workload-nsg", required=True)
    parser.add_argument("--subnet-cidr", default="10.251.0.128/26")
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    ids = plan["resource_ids"]
    network, vcn = ids["network_compartment"], ids["vcn"]
    private_cidr = plan["subnet_cidr"]
    members = [str(ipaddress.ip_address(ip)) for ip in args.members.split(",")]

    gateway = named(oci("network", "internet-gateway", "list", "--compartment-id", network, "--vcn-id", vcn,
                        "--all").get("data", []), PREFIX)
    if gateway is None:
        gateway = oci("network", "internet-gateway", "create", "--compartment-id", network, "--vcn-id", vcn,
                      "--is-enabled", "true", "--display-name", PREFIX, "--wait-for-state", "AVAILABLE")["data"]
    routes = named(oci("network", "route-table", "list", "--compartment-id", network, "--vcn-id", vcn,
                       "--all").get("data", []), PREFIX)
    if routes is None:
        routes = oci("network", "route-table", "create", "--compartment-id", network, "--vcn-id", vcn,
                     "--display-name", PREFIX, "--wait-for-state", "AVAILABLE", "--route-rules", json.dumps([{
                         "destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK",
                         "networkEntityId": gateway["id"]}]))["data"]
    rules = oci("network", "security-list", "list", "--compartment-id", network, "--vcn-id", vcn, "--all").get("data", [])
    security = named(rules, PREFIX)
    if security is None:
        security = oci("network", "security-list", "create", "--compartment-id", network, "--vcn-id", vcn,
                       "--display-name", PREFIX, "--wait-for-state", "AVAILABLE",
                       "--ingress-security-rules", json.dumps([{
                           "protocol": "6", "source": "0.0.0.0/0", "sourceType": "CIDR_BLOCK", "isStateless": False,
                           "tcpOptions": {"destinationPortRange": {"min": 443, "max": 443}}}]),
                       "--egress-security-rules", json.dumps([{
                           "protocol": "6", "destination": private_cidr, "destinationType": "CIDR_BLOCK",
                           "isStateless": False,
                           "tcpOptions": {"destinationPortRange": {"min": args.client_port,
                                                                   "max": args.client_port}}}]))["data"]
    subnet = named(oci("network", "subnet", "list", "--compartment-id", network, "--vcn-id", vcn,
                       "--all").get("data", []), PREFIX)
    if subnet is None:
        subnet = oci("network", "subnet", "create", "--compartment-id", network, "--vcn-id", vcn,
                     "--cidr-block", args.subnet_cidr, "--display-name", PREFIX, "--dns-label", "public",
                     "--prohibit-public-ip-on-vnic", "false", "--route-table-id", routes["id"],
                     "--security-list-ids", json.dumps([security["id"]]), "--wait-for-state", "AVAILABLE")["data"]

    rule_rows = oci("network", "nsg", "rules", "list", "--nsg-id", args.workload_nsg, "--all").get("data", [])
    if not any(row.get("source") == args.subnet_cidr and row.get("direction") == "INGRESS" and
               (row.get("tcp-options") or {}).get("destination-port-range", {}).get("min") == args.client_port
               for row in rule_rows):
        oci("network", "nsg", "rules", "add", "--nsg-id", args.workload_nsg, "--security-rules", json.dumps([{
            "direction": "INGRESS", "protocol": "6", "source": args.subnet_cidr, "sourceType": "CIDR_BLOCK",
            "isStateless": False, "description": "TerraBase HTTPS from the public load balancer",
            "tcpOptions": {"destinationPortRange": {"min": args.client_port, "max": args.client_port}}}]))

    balancers = oci("nlb", "network-load-balancer", "list", "--compartment-id", network, "--all").get("data", {}).get("items", [])
    balancer = named(balancers, PREFIX)
    if balancer is None:
        backend_set = {"terrabase-https": {
            "policy": "FIVE_TUPLE", "isPreserveSource": False,
            "healthChecker": {"protocol": "TCP", "port": args.client_port, "intervalInMillis": 10000,
                              "timeoutInMillis": 3000, "retries": 3},
            "backends": [{"ipAddress": ip, "port": args.client_port, "weight": 1} for ip in members]}}
        listeners = {"https": {"name": "https", "defaultBackendSetName": "terrabase-https", "port": 443,
                               "protocol": "TCP"}}
        oci("nlb", "network-load-balancer", "create", "--compartment-id", network,
            "--display-name", PREFIX, "--subnet-id", subnet["id"], "--is-private", "false",
            "--is-preserve-source-destination", "false",
            "--backend-sets", json.dumps(backend_set), "--listeners", json.dumps(listeners))
        for _ in range(90):
            balancer = named(oci("nlb", "network-load-balancer", "list", "--compartment-id", network,
                                 "--all").get("data", {}).get("items", []), PREFIX)
            if balancer is not None:
                break
            time.sleep(5)
    balancer = wait_state(["nlb", "network-load-balancer", "get", "--network-load-balancer-id", balancer["id"]],
                          "ACTIVE")
    public = [address["ip-address"] for address in balancer.get("ip-addresses", []) if address.get("is-public")]
    print(json.dumps({"network_load_balancer": balancer["id"], "public_ip": public[0] if public else None,
                      "subnet": subnet["id"], "members": members, "port": 443}))


if __name__ == "__main__":
    sys.exit(main())
