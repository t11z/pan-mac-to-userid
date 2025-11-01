#!/usr/bin/env python3
"""
user_mac_to_firewall_pan_os.py

Reads users and MAC addresses from a YAML file, finds IPs for those MACs
(using local ARP cache and ARP-scans of directly connected IPv4 networks),
builds a bulk PAN-OS uid-message payload (login entries) and posts it to
the firewall XML API (type=user-id) according to the PAN-OS doc examples.

Linux-only assumptions for interface enumeration: uses "ip -4 addr show".
Requires root for ARP scanning with scapy.
"""

from typing import Dict, List, Tuple
from ipaddress import IPv4Network, ip_network, ip_address
import subprocess
import re
import yaml
import logging
import argparse
import sys
import requests

# OPTIONAL: scapy for ARP scan
try:
    from scapy.all import srp, Ether, ARP, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def normalize_mac(mac: str) -> str:
    return mac.lower().replace("-", ":").replace(".", ":").replace(" ", "")


def parse_arp_cache() -> Dict[str, str]:
    """
    Parse local ARP cache (arp -a) into mac -> ip mapping.
    """
    mac_to_ip: Dict[str, str] = {}
    try:
        res = subprocess.check_output(["arp", "-a"], universal_newlines=True, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.debug("arp -a not available: %s", e)
        return mac_to_ip

    for line in res.splitlines():
        ip_match = re.search(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?", line)
        mac_match = re.search(
            r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
            line,
        )
        if ip_match and mac_match:
            ip = ip_match.group(1)
            mac = normalize_mac(mac_match.group(1))
            mac_to_ip[mac] = ip
    return mac_to_ip


def get_directly_connected_ipv4_networks() -> List[Tuple[str, IPv4Network]]:
    """
    Use 'ip -4 addr show' to enumerate IPv4 addresses and derive directly connected networks.
    Returns list of (iface, IPv4Network).
    """
    networks: List[Tuple[str, IPv4Network]] = []
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show"], universal_newlines=True)
    except Exception as e:
        logging.error("Failed to run 'ip -4 addr show': %s", e)
        return networks

    iface = None
    for line in out.splitlines():
        m_iface = re.match(r"^\d+:\s+([^:]+):\s+<([^>]+)>", line)
        if m_iface:
            iface = m_iface.group(1)
            continue
        if iface is None:
            continue
        addr_match = re.search(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})", line)
        if addr_match:
            ip_str = addr_match.group(1)
            prefix = int(addr_match.group(2))
            if iface == "lo":
                continue
            try:
                net = IPv4Network(f"{ip_str}/{prefix}", strict=False)
                if net.prefixlen == 32:
                    continue
                networks.append((iface, net))
            except Exception as e:
                logging.debug("Skipping invalid network for %s %s/%s: %s", iface, ip_str, prefix, e)

    # deduplicate by network address+prefix
    unique: Dict[Tuple[str, int], Tuple[str, IPv4Network]] = {}
    for iface, net in networks:
        key = (str(net.network_address), net.prefixlen)
        if key not in unique:
            unique[key] = (iface, net)
    return list(unique.values())


def arp_scan_network(interface: str, network: IPv4Network, timeout: int = 2) -> Dict[str, str]:
    """
    ARP-scan the given IPv4 network on the given interface using scapy.
    Returns mac -> ip mapping.
    """
    results: Dict[str, str] = {}
    if not SCAPY_AVAILABLE:
        logging.debug("Scapy not available; skipping ARP scan for %s on %s", network, interface)
        return results
    try:
        conf.verb = 0
        pdst = str(network)
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst), timeout=timeout, retry=1, iface=interface)
        for _, recv in answered:
            mac = normalize_mac(recv.hwsrc)
            ip = recv.psrc
            results[mac] = ip
        return results
    except PermissionError:
        logging.error("Root privileges required for ARP scanning with scapy on interface %s", interface)
        return {}
    except Exception as e:
        logging.error("Error during ARP scan on %s (%s): %s", interface, network, e)
        return {}


def find_ip_for_mac(mac: str, arp_cache: Dict[str, str], scan_cache: Dict[str, str]) -> str:
    macn = normalize_mac(mac)
    if macn in arp_cache:
        return arp_cache[macn]
    if macn in scan_cache:
        return scan_cache[macn]
    return None


def build_uid_login_payload(mappings: List[Tuple[str, str]], timeout: int = None, domain: str = None) -> str:
    """
    Build a PAN-OS uid-message payload (bulk <login> entries).
    mappings: list of (username, ip)
    timeout: optional timeout attribute in seconds on each entry
    domain: optional domain prefix to apply to each username as domain\\username
    Returns the XML string payload conforming to examples in PAN-OS doc.
    """
    entries = []
    for user, ip in mappings:
        name = f"{domain}\\{user}" if domain else user
        timeout_attr = f' timeout="{int(timeout)}"' if timeout is not None else ""
        entries.append(f'<entry name="{xml_escape(name)}" ip="{xml_escape(ip)}"{timeout_attr}/>')

    inner = "".join(entries)
    payload = (
        "<uid-message>"
        "<version>1.0</version>"
        "<type>update</type>"
        "<payload>"
        "<login>"
        f"{inner}"
        "</login>"
        "</payload>"
        "</uid-message>"
    )
    return payload


def xml_escape(text: str) -> str:
    """
    Minimal XML escaping for attribute values.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def send_uid_payload(api_url: str, api_key: str, payload: str, verify_ssl: bool = True, timeout: int = 15) -> Tuple[bool, int, str]:
    """
    Send the uid payload to the PAN-OS XML API using the 'cmd' form as urlencoded data.
    Returns tuple (ok, status_code, response_text).
    """
    # Use the "cmd" approach: type=user-id, key=..., cmd=<xml>
    data = {
        "type": "user-id",
        "key": api_key,
        "cmd": payload,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        r = requests.post(api_url, data=data, headers=headers, timeout=timeout, verify=verify_ssl)
        # Always return the status and text for debugging
        try:
            r.raise_for_status()
            return True, r.status_code, r.text
        except requests.HTTPError:
            return False, r.status_code, r.text
    except requests.RequestException as e:
        return False, -1, str(e)


def main(yaml_path: str, api_url: str, api_key: str, scan_timeout: int = 2, verify_ssl: bool = True, domain: str = None, entry_timeout: int = None) -> int:
    # optionally suppress insecure request warning if verify_ssl is False
    if not verify_ssl:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    data = load_yaml(yaml_path)
    if not data or "users" not in data:
        logging.error("YAML file does not contain 'users' list")
        return 1

    arp_cache = parse_arp_cache()
    logging.info("Parsed ARP cache entries: %d", len(arp_cache))

    iface_nets = get_directly_connected_ipv4_networks()
    if iface_nets:
        logging.info("Discovered %d directly connected IPv4 networks", len(iface_nets))
    else:
        logging.info("No directly connected IPv4 networks discovered; will rely on ARP cache only")

    # aggregate scan results
    scan_cache: Dict[str, str] = {}
    for iface, net in iface_nets:
        logging.info("Scanning network %s on interface %s", net, iface)
        res = arp_scan_network(iface, net, timeout=scan_timeout)
        if res:
            logging.info("Found %d hosts in %s", len(res), net)
            scan_cache.update(res)
        else:
            logging.debug("No hosts discovered in scan on %s (%s)", iface, net)

    # build mappings list (username, ip) for all found IPs
    mappings: List[Tuple[str, str]] = []
    failures = []
    for user in data["users"]:
        user_id = user.get("id")
        macs = user.get("macs", []) or []
        if not user_id:
            logging.warning("Skipping entry without id")
            continue
        for mac in macs:
            ip = find_ip_for_mac(mac, arp_cache, scan_cache)
            if not ip:
                logging.info("No IP found for MAC %s (user %s)", mac, user_id)
                failures.append({"user": user_id, "mac": mac, "reason": "no-ip"})
                continue
            try:
                ip_address(ip)  # validate
            except Exception:
                logging.warning("Invalid IP %s for MAC %s (user %s)", ip, mac, user_id)
                failures.append({"user": user_id, "mac": mac, "ip": ip, "reason": "invalid-ip"})
                continue
            mappings.append((user_id, ip))

    if not mappings:
        logging.info("No mappings to send; exiting")
        return 0

    # build bulk payload (all login entries in one uid-message)
    payload = build_uid_login_payload(mappings, timeout=entry_timeout, domain=domain)
    logging.debug("Built UID payload:\n%s", payload)

    # ensure api_url ends with /api/
    if not api_url.rstrip("/").endswith("/api"):
        api_url = api_url.rstrip("/") + "/api/"

    # send the payload
    ok, status_code, resp_text = send_uid_payload(api_url, api_key, payload, verify_ssl=verify_ssl)
    if ok:
        logging.info("API request successful: HTTP %s", status_code)
    else:
        logging.error("API request failed: HTTP %s", status_code)

    # always log the response body for debugging
    logging.info("API response body:\n%s", resp_text)

    # response XML typically contains <result><status>success</status></result> or failure details
    return 0 if ok else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bulk send User-ID mappings to Palo Alto PAN-OS XML API (type=user-id)")
    parser.add_argument("yaml", help="Path to YAML file with users and macs")
    parser.add_argument("--api-url", required=True, help="Firewall API URL (e.g. https://firewall.example.local/api/)")
    parser.add_argument("--api-key", required=True, help="API key for the firewall")
    parser.add_argument("--scan-timeout", type=int, default=2, help="ARP scan timeout seconds per network")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification and suppress related warnings")
    parser.add_argument("--domain", help="Optional domain prefix to prepend to usernames as domain\\user")
    parser.add_argument("--entry-timeout", type=int, help="Optional timeout attribute for each login entry (seconds)")
    args = parser.parse_args()

    sys.exit(main(args.yaml, args.api_url, args.api_key, scan_timeout=args.scan_timeout, verify_ssl=not args.no_verify_ssl, domain=args.domain, entry_timeout=args.entry_timeout))
