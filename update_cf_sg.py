#!/usr/bin/env python3
"""
Production-safe, per-port Cloudflare <> AWS SG incremental sync.

Usage:
  sudo python3 update_cf_sg.py [--dry-run] [--debug]

--dry-run : show planned changes only
--debug   : print extra debug (full per-port lists)
"""
import os
import sys
import time
import json
import argparse
import ipaddress
import requests
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from dotenv import load_dotenv

# --- config ---
load_dotenv('/home/ubuntu/.env')

SECURITY_GROUP_ID = os.getenv("SECURITY_GROUP_ID")
AWS_REGION = os.getenv("AWS_REGION")
PORTS = [int(p.strip()) for p in os.getenv("PORTS", "80,443").split(",")]
LOG_FILE = os.getenv("LOG_FILE", "/var/log/cf_sg_sync.log")

CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4/ips"
BATCH_SIZE = 40
HTTP_TIMEOUT = 15
HTTP_RETRIES = 4
HTTP_BACKOFF = 1.5

ec2 = boto3.client("ec2", region_name=AWS_REGION)

# --- helpers ---
def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def log(msg):
    line = f"[{ts()}] {msg}"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)

def normalize(cidr):
    return str(ipaddress.ip_network(cidr, strict=False))

def chunked(iterable, n):
    lst = list(iterable)
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def retry_get(url, timeout=HTTP_TIMEOUT, retries=HTTP_RETRIES, backoff=HTTP_BACKOFF):
    last = None
    for i in range(retries):
        try:
            return requests.get(url, timeout=timeout)
        except Exception as e:
            last = e
            time.sleep(backoff ** i)
    raise last

# --- fetch cloudflare ---
def fetch_cloudflare():
    r = retry_get(CLOUDFLARE_API_URL)
    r.raise_for_status()
    data = r.json().get("result", {})
    cf_v4 = {normalize(c) for c in data.get("ipv4_cidrs", [])}
    cf_v6 = {normalize(c) for c in data.get("ipv6_cidrs", [])}
    return cf_v4, cf_v6

# --- fetch SG per-port ---
def fetch_sg_per_port():
    """Return dicts: port -> set(ipv4 cidrs), port -> set(ipv6 cidrs)"""
    sg = ec2.describe_security_groups(GroupIds=[SECURITY_GROUP_ID])["SecurityGroups"][0]
    per_port_v4 = {p: set() for p in PORTS}
    per_port_v6 = {p: set() for p in PORTS}

    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") != "tcp":
            continue
        fp = perm.get("FromPort")
        tp = perm.get("ToPort")
        # skip perms without numeric ports
        if fp is None or tp is None:
            continue
        # for each of our target ports, if this permission covers it, gather the cidrs
        for port in PORTS:
            if fp <= port <= tp:
                for r in perm.get("IpRanges", []):
                    cidr = r.get("CidrIp")
                    if cidr:
                        per_port_v4[port].add(normalize(cidr))
                for r6 in perm.get("Ipv6Ranges", []):
                    cidr6 = r6.get("CidrIpv6")
                    if cidr6:
                        per_port_v6[port].add(normalize(cidr6))
    return per_port_v4, per_port_v6

# --- plan per-port changes ---
def plan_per_port(cf_v4, cf_v6, sg_v4_map, sg_v6_map):
    add_map_v4 = {}
    del_map_v4 = {}
    add_map_v6 = {}
    del_map_v6 = {}

    for port in PORTS:
        sg_v4 = sg_v4_map.get(port, set())
        sg_v6 = sg_v6_map.get(port, set())

        add_map_v4[port] = sorted(list(cf_v4 - sg_v4), key=lambda x: (ipaddress.ip_network(x).version, ipaddress.ip_network(x)))
        del_map_v4[port] = sorted(list(sg_v4 - cf_v4), key=lambda x: (ipaddress.ip_network(x).version, ipaddress.ip_network(x)))
        add_map_v6[port] = sorted(list(cf_v6 - sg_v6), key=lambda x: (ipaddress.ip_network(x).version, ipaddress.ip_network(x)))
        del_map_v6[port] = sorted(list(sg_v6 - cf_v6), key=lambda x: (ipaddress.ip_network(x).version, ipaddress.ip_network(x)))

    return add_map_v4, del_map_v4, add_map_v6, del_map_v6

# --- apply operations (add first, then delete) ---
def apply_adds(add_map_v4, add_map_v6, dry_run=False):
    for port in PORTS:
        v4 = add_map_v4.get(port, [])
        v6 = add_map_v6.get(port, [])

        # IPv4 batches
        for batch in chunked(v4, BATCH_SIZE):
            ip_permissions = [{
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": ip} for ip in batch]
            }]
            if dry_run:
                log(f"[DRY] Would authorize IPv4 {len(batch)} on port {port}")
            else:
                try:
                    ec2.authorize_security_group_ingress(GroupId=SECURITY_GROUP_ID, IpPermissions=ip_permissions)
                    log(f"Authorized IPv4 {len(batch)} on port {port}")
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code == "InvalidPermission.Duplicate":
                        log(f"Some IPv4 already existed on port {port} (ok).")
                    else:
                        log(f"Error authorizing IPv4 on port {port}: {e}")

        # IPv6 batches
        for batch in chunked(v6, BATCH_SIZE):
            ip_permissions = [{
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "Ipv6Ranges": [{"CidrIpv6": ip} for ip in batch]
            }]
            if dry_run:
                log(f"[DRY] Would authorize IPv6 {len(batch)} on port {port}")
            else:
                try:
                    ec2.authorize_security_group_ingress(GroupId=SECURITY_GROUP_ID, IpPermissions=ip_permissions)
                    log(f"Authorized IPv6 {len(batch)} on port {port}")
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code == "InvalidPermission.Duplicate":
                        log(f"Some IPv6 already existed on port {port} (ok).")
                    else:
                        log(f"Error authorizing IPv6 on port {port}: {e}")

def apply_deletes(del_map_v4, del_map_v6, dry_run=False):
    for port in PORTS:
        v4 = del_map_v4.get(port, [])
        v6 = del_map_v6.get(port, [])

        for batch in chunked(v4, BATCH_SIZE):
            ip_permissions = [{
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": ip} for ip in batch]
            }]
            if dry_run:
                log(f"[DRY] Would revoke IPv4 {len(batch)} on port {port}")
            else:
                try:
                    ec2.revoke_security_group_ingress(GroupId=SECURITY_GROUP_ID, IpPermissions=ip_permissions)
                    log(f"Revoked IPv4 {len(batch)} on port {port}")
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code == "InvalidPermission.NotFound":
                        log(f"Some IPv4 already absent on port {port} (ok).")
                    else:
                        log(f"Error revoking IPv4 on port {port}: {e}")

        for batch in chunked(v6, BATCH_SIZE):
            ip_permissions = [{
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "Ipv6Ranges": [{"CidrIpv6": ip} for ip in batch]
            }]
            if dry_run:
                log(f"[DRY] Would revoke IPv6 {len(batch)} on port {port}")
            else:
                try:
                    ec2.revoke_security_group_ingress(GroupId=SECURITY_GROUP_ID, IpPermissions=ip_permissions)
                    log(f"Revoked IPv6 {len(batch)} on port {port}")
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code == "InvalidPermission.NotFound":
                        log(f"Some IPv6 already absent on port {port} (ok).")
                    else:
                        log(f"Error revoking IPv6 on port {port}: {e}")

# --- main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Don't apply changes, just show plan")
    parser.add_argument("--debug", action="store_true", help="Show detailed per-port lists")
    args = parser.parse_args()
    dry = args.dry_run
    debug = args.debug

    try:
        log("Starting Cloudflare SG sync (per-port strict mode)...")
        cf_v4, cf_v6 = fetch_cloudflare()
        sg_v4_map, sg_v6_map = fetch_sg_per_port()

        add_map_v4, del_map_v4, add_map_v6, del_map_v6 = plan_per_port(cf_v4, cf_v6, sg_v4_map, sg_v6_map)

        # summary
        for port in PORTS:
            log(f"Port {port}: CF IPv4={len(cf_v4)} SG IPv4={len(sg_v4_map.get(port, []))} | "
                f"CF IPv6={len(cf_v6)} SG IPv6={len(sg_v6_map.get(port, []))}")
            log(f"  Plan for port {port}: +v4={len(add_map_v4.get(port, []))} -v4={len(del_map_v4.get(port, []))} "
                f"+v6={len(add_map_v6.get(port, []))} -v6={len(del_map_v6.get(port, []))}")

            if debug:
                log(f"  SG_v4[{port}] sample: {list(sg_v4_map.get(port, []))[:8]}")
                log(f"  SG_v6[{port}] sample: {list(sg_v6_map.get(port, []))[:8]}")

        any_changes = any(len(add_map_v4[p]) or len(del_map_v4[p]) or len(add_map_v6[p]) or len(del_map_v6[p]) for p in PORTS)
        if not any_changes:
            log("Security group already matches Cloudflare IPs on all ports. Nothing to do.")
            return

        # Add first, then remove
        apply_adds(add_map_v4, add_map_v6, dry_run=dry)
        apply_deletes(del_map_v4, del_map_v6, dry_run=dry)

        if dry:
            log("Dry-run finished. No changes applied.")
        else:
            log("Cloudflare SG sync completed successfully.")
    except Exception as e:
        log(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
