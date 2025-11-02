#!/usr/bin/env python3
"""
user_mac_to_firewall_pan_os.py

Reads users and MAC addresses from a YAML file, finds IPs for those MACs
(using local ARP/NDP cache and ARP/NDP scans of directly connected IPv4 and
IPv6 networks), builds a bulk PAN-OS uid-message payload (login entries) and posts it to
the firewall XML API (type=user-id) according to the PAN-OS doc examples.

Linux-only assumptions for interface enumeration: uses "ip -4 addr show" and
"ip -6 addr show".
Requires root for ARP/NDP scanning with scapy.
"""

from typing import Dict, List, Tuple, Optional
from ipaddress import IPv4Network, ip_address
import subprocess
import re
import yaml
import logging
import argparse
import sys
import requests

# OPTIONAL: scapy for ARP/NDP scan
try:
    from scapy.all import srp, Ether, ARP, conf, IPv6, ICMPv6EchoRequest
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


def normalize_interface_name(name: str) -> str:
    """Strip parent interface suffixes (e.g. veth0@if5 -> veth0)."""

    if "@" in name:
        return name.split("@", 1)[0]
    return name


def merge_mac_ip_map(target: Dict[str, List[str]], source: Dict[str, List[str]]) -> None:
    for mac, ips in source.items():
        macn = normalize_mac(mac)
        if not ips:
            continue
        existing = target.setdefault(macn, [])
        for ip in ips:
            if ip not in existing:
                existing.append(ip)


def count_mac_ip_entries(mapping: Dict[str, List[str]]) -> int:
    return sum(len(ips) for ips in mapping.values())


def parse_arp_cache() -> Dict[str, List[str]]:
    """
    Parse local ARP cache (arp -a) into mac -> ip mapping.
    """
    mac_to_ip: Dict[str, List[str]] = {}
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
            mac_to_ip.setdefault(mac, [])
            if ip not in mac_to_ip[mac]:
                mac_to_ip[mac].append(ip)
    return mac_to_ip


def parse_ndp_cache() -> Dict[str, List[str]]:
    mac_to_ip: Dict[str, List[str]] = {}
    try:
        res = subprocess.check_output(["ip", "-6", "neigh"], universal_newlines=True, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.debug("ip -6 neigh not available: %s", e)
        return mac_to_ip

    for line in res.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        if "lladdr" not in parts:
            continue
        if "FAILED" in parts:
            continue
        try:
            mac_index = parts.index("lladdr") + 1
            mac = normalize_mac(parts[mac_index])
        except Exception:
            continue
        mac_to_ip.setdefault(mac, [])
        if ip not in mac_to_ip[mac]:
            mac_to_ip[mac].append(ip)
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
            iface = normalize_interface_name(m_iface.group(1))
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


def get_ipv6_enabled_interfaces() -> List[str]:
    interfaces: List[str] = []
    try:
        out = subprocess.check_output(["ip", "-6", "addr", "show"], universal_newlines=True)
    except Exception as e:
        logging.error("Failed to run 'ip -6 addr show': %s", e)
        return interfaces

    iface = None
    has_ipv6 = False
    for line in out.splitlines():
        m_iface = re.match(r"^\d+:\s+([^:]+):\s+<([^>]+)>", line)
        if m_iface:
            if iface and has_ipv6 and iface != "lo":
                interfaces.append(iface)
            iface = normalize_interface_name(m_iface.group(1))
            has_ipv6 = False
            continue
        if iface is None:
            continue
        if "inet6" in line and " scope host" not in line:
            has_ipv6 = True
    if iface and has_ipv6 and iface != "lo":
        interfaces.append(iface)
    return interfaces


def arp_scan_network(interface: str, network: IPv4Network, timeout: int = 2) -> Dict[str, List[str]]:
    """
    ARP-scan the given IPv4 network on the given interface using scapy.
    Returns mac -> ip mapping.
    """
    results: Dict[str, List[str]] = {}
    if not SCAPY_AVAILABLE:
        logging.debug("Scapy not available; skipping ARP scan for %s on %s", network, interface)
        return results
    try:
        conf.verb = 0
        pdst = str(network)
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst),
            timeout=timeout,
            retry=1,
            iface=interface,
        )
        for _, recv in answered:
            mac = normalize_mac(recv.hwsrc)
            ip = recv.psrc
            results.setdefault(mac, [])
            if ip not in results[mac]:
                results[mac].append(ip)
        return results
    except PermissionError:
        logging.error("Root privileges required for ARP scanning with scapy on interface %s", interface)
        return {}
    except Exception as e:
        logging.error("Error during ARP scan on %s (%s): %s", interface, network, e)
        return {}


def ndp_scan_interface(interface: str, timeout: int = 2) -> Dict[str, List[str]]:
    """Send an IPv6 all-nodes multicast probe to populate the neighbor cache."""

    results: Dict[str, List[str]] = {}
    if not SCAPY_AVAILABLE:
        logging.debug("Scapy not available; skipping IPv6 scan on %s", interface)
        return results
    try:
        conf.verb = 0
        packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()
        answered, _ = srp(packet, timeout=timeout, iface=interface, multi=True)
        for _, recv in answered:
            if IPv6 not in recv:
                continue
            mac = normalize_mac(recv[Ether].src)
            ip = recv[IPv6].src
            results.setdefault(mac, [])
            if ip not in results[mac]:
                results[mac].append(ip)
        return results
    except PermissionError:
        logging.error("Root privileges required for IPv6 scanning with scapy on interface %s", interface)
        return {}
    except Exception as e:
        logging.error("Error during IPv6 scan on interface %s: %s", interface, e)
        return {}


def find_ips_for_mac(mac: str, mac_ip_map: Dict[str, List[str]]) -> List[str]:
    macn = normalize_mac(mac)
    return mac_ip_map.get(macn, [])


def build_uid_payload(
    mappings: List[Tuple[str, str]],
    user_tags: Dict[str, List[Tuple[str, Optional[int]]]],
    timeout: int = None,
    domain: str = None,
) -> str:
    """
    Build a PAN-OS uid-message payload including login and register-user entries.
    mappings: list of (username, ip)
    user_tags: mapping of username -> list of (tag, optional timeout)
    timeout: optional timeout attribute in seconds on each login entry
    domain: optional domain prefix to apply to each username as domain\\username
    Returns the XML string payload conforming to PAN-OS doc examples.
    """

    login_entries = []
    for user, ip in mappings:
        name = f"{domain}\\{user}" if domain else user
        timeout_attr = f' timeout="{int(timeout)}"' if timeout is not None else ""
        login_entries.append(f'<entry name="{xml_escape(name)}" ip="{xml_escape(ip)}"{timeout_attr}/>')

    register_entries = []
    for user, tags in user_tags.items():
        if not tags:
            continue
        name = f"{domain}\\{user}" if domain else user
        tag_members = []
        for tag, tag_timeout in tags:
            timeout_attr = f' timeout="{int(tag_timeout)}"' if tag_timeout is not None else ""
            tag_members.append(f'<member{timeout_attr}>{xml_escape(tag)}</member>')
        register_entries.append(
            f'<entry user="{xml_escape(name)}"><tag>{"".join(tag_members)}</tag></entry>'
        )

    payload_parts = [
        "<uid-message>",
        "<version>1.0</version>",
        "<type>update</type>",
        "<payload>",
    ]

    if login_entries:
        payload_parts.append("<login>")
        payload_parts.append("".join(login_entries))
        payload_parts.append("</login>")

    if register_entries:
        payload_parts.append("<register-user>")
        payload_parts.append("".join(register_entries))
        payload_parts.append("</register-user>")

    payload_parts.extend(["</payload>", "</uid-message>"])
    return "".join(payload_parts)


def parse_user_tags(raw_tags: List, user_id: str) -> List[Tuple[str, Optional[int]]]:
    """Normalize YAML tag definitions into (name, timeout) tuples."""

    normalized: List[Tuple[str, Optional[int]]] = []
    for tag in raw_tags or []:
        tag_name: Optional[str] = None
        tag_timeout: Optional[int] = None

        if isinstance(tag, str):
            tag_name = tag
        elif isinstance(tag, dict):
            if "name" in tag:
                tag_name = tag.get("name")
                if "timeout" in tag:
                    tag_timeout = _coerce_timeout(tag.get("timeout"), user_id, tag_name)
            elif len(tag) == 1:
                tag_name, timeout_value = next(iter(tag.items()))
                tag_timeout = _coerce_timeout(timeout_value, user_id, tag_name)
            else:
                logging.warning("Skipping invalid tag definition for user %s: %s", user_id, tag)
                continue
        else:
            logging.warning("Skipping invalid tag definition for user %s: %s", user_id, tag)
            continue

        if not tag_name:
            logging.warning("Skipping tag with empty name for user %s", user_id)
            continue

        normalized.append((str(tag_name), tag_timeout))

    return normalized


def _coerce_timeout(value, user_id: str, tag_name: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        timeout_int = int(value)
        if timeout_int < 0:
            raise ValueError("timeout must be non-negative")
        return timeout_int
    except Exception:
        logging.warning(
            "Invalid timeout '%s' for tag %s (user %s); ignoring", value, tag_name, user_id
        )
        return None


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

    mac_ip_map: Dict[str, List[str]] = {}

    arp_cache = parse_arp_cache()
    if arp_cache:
        logging.info("Parsed ARP cache entries: %d", count_mac_ip_entries(arp_cache))
        merge_mac_ip_map(mac_ip_map, arp_cache)
    else:
        logging.info("No ARP cache entries found")

    ndp_cache = parse_ndp_cache()
    if ndp_cache:
        logging.info("Parsed NDP cache entries: %d", count_mac_ip_entries(ndp_cache))
        merge_mac_ip_map(mac_ip_map, ndp_cache)
    else:
        logging.info("No NDP cache entries found")

    iface_nets = get_directly_connected_ipv4_networks()
    if iface_nets:
        logging.info("Discovered %d directly connected IPv4 networks", len(iface_nets))
    else:
        logging.info("No directly connected IPv4 networks discovered; will rely on ARP/NDP cache")

    for iface, net in iface_nets:
        logging.info("Scanning IPv4 network %s on interface %s", net, iface)
        res = arp_scan_network(iface, net, timeout=scan_timeout)
        if res:
            logging.info("Found %d IPv4 hosts in %s", count_mac_ip_entries(res), net)
            merge_mac_ip_map(mac_ip_map, res)
        else:
            logging.debug("No hosts discovered in scan on %s (%s)", iface, net)

    ipv6_ifaces = get_ipv6_enabled_interfaces()
    if ipv6_ifaces:
        logging.info("Discovered %d interfaces with IPv6 addresses", len(ipv6_ifaces))
    else:
        logging.info("No IPv6-enabled interfaces discovered")

    for iface in ipv6_ifaces:
        logging.info("Sending IPv6 probe on interface %s", iface)
        res = ndp_scan_interface(iface, timeout=scan_timeout)
        if res:
            logging.info("Found %d IPv6 hosts on %s", count_mac_ip_entries(res), iface)
            merge_mac_ip_map(mac_ip_map, res)
        else:
            logging.debug("No IPv6 hosts discovered on interface %s", iface)

    # build mappings list (username, ip) for all found IPs
    mappings: List[Tuple[str, str]] = []
    failures = []
    user_tags_map: Dict[str, List[Tuple[str, Optional[int]]]] = {}
    for user in data["users"]:
        user_id = user.get("id")
        macs = user.get("macs", []) or []
        if not user_id:
            logging.warning("Skipping entry without id")
            continue
        tags = parse_user_tags(user.get("tags", []), user_id)
        if tags:
            user_tags_map[user_id] = tags
        for mac in macs:
            ips = find_ips_for_mac(mac, mac_ip_map)
            if not ips:
                logging.info("No IP found for MAC %s (user %s)", mac, user_id)
                failures.append({"user": user_id, "mac": mac, "reason": "no-ip"})
                continue
            for ip in ips:
                try:
                    ip_address(ip)  # validate
                except Exception:
                    logging.warning("Invalid IP %s for MAC %s (user %s)", ip, mac, user_id)
                    failures.append({"user": user_id, "mac": mac, "ip": ip, "reason": "invalid-ip"})
                    continue
                mappings.append((user_id, ip))

    if mappings:
        unique_mappings: List[Tuple[str, str]] = []
        seen_pairs = set()
        for entry in mappings:
            if entry not in seen_pairs:
                seen_pairs.add(entry)
                unique_mappings.append(entry)
        mappings = unique_mappings

    if not mappings and not any(user_tags_map.values()):
        logging.info("No mappings or tags to send; exiting")
        return 0

    # build bulk payload (all login entries in one uid-message)
    payload = build_uid_payload(
        mappings,
        user_tags_map,
        timeout=entry_timeout,
        domain=domain,
    )
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
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=2,
        help="Layer 2 scan timeout seconds per network/interface",
    )
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification and suppress related warnings")
    parser.add_argument("--domain", help="Optional domain prefix to prepend to usernames as domain\\user")
    parser.add_argument("--entry-timeout", type=int, help="Optional timeout attribute for each login entry (seconds)")
    args = parser.parse_args()

    sys.exit(main(args.yaml, args.api_url, args.api_key, scan_timeout=args.scan_timeout, verify_ssl=not args.no_verify_ssl, domain=args.domain, entry_timeout=args.entry_timeout))
