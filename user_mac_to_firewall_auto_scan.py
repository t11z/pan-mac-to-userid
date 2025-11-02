#!/usr/bin/env python3
"""
user_mac_to_firewall_pan_os.py

Reads users and MAC addresses from a YAML file, finds IPs for those MACs
(using local ARP cache and ARP-scans of directly connected IPv4 networks
plus IPv6 NDP data/scans), builds a bulk PAN-OS uid-message payload
(login and optional register-user tag entries) and posts it to the
firewall XML API (type=user-id) according to the PAN-OS doc examples.

Linux-only assumptions for interface enumeration: uses "ip -4 addr show".
Requires root for ARP scanning with scapy.
"""

from typing import Dict, List, Tuple, Iterable, Set, Optional
from ipaddress import IPv4Network, IPv6Network, ip_address
from collections import defaultdict
import subprocess
import re
import yaml
import logging
import argparse
import sys
import requests

# OPTIONAL: scapy for ARP scan
try:
    from scapy.all import (
        srp,
        Ether,
        ARP,
        conf,
        IPv6,
        ICMPv6ND_NS,
        ICMPv6ND_NA,
        ICMPv6NDOptSrcLLAddr,
        get_if_hwaddr,
    )
    from scapy.layers.inet6 import in6_getnsma, in6_getnsmac
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


def parse_ndp_cache() -> Dict[str, str]:
    """Parse IPv6 neighbor cache into mac -> ipv6 mapping."""
    mac_to_ip: Dict[str, str] = {}
    try:
        res = subprocess.check_output(
            ["ip", "-6", "neigh", "show"], universal_newlines=True, stderr=subprocess.DEVNULL
        )
    except Exception as e:
        logging.debug("ip -6 neigh not available: %s", e)
        return mac_to_ip

    for line in res.splitlines():
        line = line.strip()
        if not line or "lladdr" not in line:
            continue
        ip_match = re.match(r"([0-9a-fA-F:]+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:-]{17})", line)
        if not ip_match:
            continue
        ipv6 = ip_match.group(1)
        mac = normalize_mac(ip_match.group(2))
        mac_to_ip[mac] = ipv6
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


def get_directly_connected_ipv6_networks() -> List[Tuple[str, IPv6Network]]:
    """Enumerate directly connected IPv6 networks using 'ip -6 addr show'."""
    networks: List[Tuple[str, IPv6Network]] = []
    try:
        out = subprocess.check_output(["ip", "-6", "addr", "show"], universal_newlines=True)
    except Exception as e:
        logging.error("Failed to run 'ip -6 addr show': %s", e)
        return networks

    iface = None
    for line in out.splitlines():
        m_iface = re.match(r"^\d+:\s+([^:]+):\s+<([^>]+)>", line)
        if m_iface:
            iface = m_iface.group(1)
            continue
        if iface is None:
            continue
        addr_match = re.search(r"inet6\s+([0-9a-fA-F:]+)/([0-9]{1,3})", line)
        if addr_match:
            ip_str = addr_match.group(1)
            prefix = int(addr_match.group(2))
            if iface == "lo":
                continue
            try:
                net = IPv6Network(f"{ip_str}/{prefix}", strict=False)
                if net.prefixlen == 128:
                    continue
                networks.append((iface, net))
            except Exception as e:
                logging.debug(
                    "Skipping invalid IPv6 network for %s %s/%s: %s", iface, ip_str, prefix, e
                )

    unique: Dict[Tuple[str, int], Tuple[str, IPv6Network]] = {}
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


def ndp_scan_network(
    interface: str, network: IPv6Network, timeout: int = 2, max_hosts: int = 256
) -> Dict[str, str]:
    """Perform a basic IPv6 NDP scan on the given interface and network."""
    results: Dict[str, str] = {}
    if not SCAPY_AVAILABLE:
        logging.debug("Scapy not available; skipping NDP scan for %s on %s", network, interface)
        return results

    # avoid attempting to iterate gigantic IPv6 networks
    if network.num_addresses > max_hosts:
        logging.debug(
            "Skipping NDP scan for %s on %s due to large network size (%d hosts)",
            network,
            interface,
            network.num_addresses,
        )
        return results

    try:
        conf.verb = 0
        src_ll = get_if_hwaddr(interface)
    except Exception as e:
        logging.error("Failed to get hardware address for %s: %s", interface, e)
        return results

    try:
        packets = []
        for ip in network.hosts():
            target = str(ip)
            solicited_ip = in6_getnsma(target)
            dst_mac = in6_getnsmac(target)
            pkt = (
                Ether(dst=dst_mac)
                / IPv6(dst=solicited_ip)
                / ICMPv6ND_NS(tgt=target)
                / ICMPv6NDOptSrcLLAddr(lladdr=src_ll)
            )
            packets.append(pkt)

        if not packets:
            return results

        answered_all = []
        for pkt in packets:
            answered, _ = srp(pkt, timeout=timeout, iface=interface, multi=True)
            if answered:
                answered_all.extend(answered)
        for _, recv in answered_all:
            if ICMPv6ND_NA not in recv:
                continue
            mac = normalize_mac(recv[Ether].src)
            ip_addr = recv[IPv6].src
            results[mac] = ip_addr
        return results
    except PermissionError:
        logging.error("Root privileges required for NDP scanning with scapy on interface %s", interface)
        return {}
    except Exception as e:
        logging.error("Error during NDP scan on %s (%s): %s", interface, network, e)
        return {}


def find_ips_for_mac(mac: str, mac_to_ips: Dict[str, Iterable[str]]) -> List[str]:
    macn = normalize_mac(mac)
    ips = mac_to_ips.get(macn)
    if not ips:
        return []
    return sorted({ip for ip in ips if ip})


def parse_user_tags(raw_tags: Iterable) -> List[Tuple[str, Optional[int]]]:
    """Parse tag definitions from YAML into (name, timeout) tuples."""
    parsed: List[Tuple[str, Optional[int]]] = []
    if not raw_tags:
        return parsed

    for item in raw_tags:
        name = None
        timeout = None
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            if "name" in item:
                name = item.get("name")
                timeout = item.get("timeout")
            elif len(item) == 1:
                name, timeout = next(iter(item.items()))
        if not name:
            logging.warning("Skipping invalid tag definition: %s", item)
            continue
        if timeout is not None:
            try:
                timeout = int(timeout)
            except (TypeError, ValueError):
                logging.warning("Invalid timeout for tag %s: %s", name, timeout)
                timeout = None
        parsed.append((str(name), timeout))
    return parsed


def build_uid_payload(
    mappings: List[Tuple[str, str]],
    tags: Dict[str, List[Tuple[str, Optional[int]]]],
    timeout: int = None,
    domain: str = None,
) -> str:
    """
    Build a PAN-OS uid-message payload including <login> and optional <register-user> entries.
    mappings: list of (username, ip)
    tags: mapping of username -> [(tag, timeout)]
    timeout: optional timeout attribute in seconds on each login entry
    domain: optional domain prefix to apply to each username as domain\\username
    Returns the XML string payload conforming to examples in PAN-OS doc.
    """
    login_entries: List[str] = []
    for user, ip in mappings:
        name = f"{domain}\\{user}" if domain else user
        timeout_attr = f' timeout="{int(timeout)}"' if timeout is not None else ""
        login_entries.append(
            f'<entry name="{xml_escape(name)}" ip="{xml_escape(ip)}"{timeout_attr}/>'
        )

    register_entries: List[str] = []
    for user, user_tags in tags.items():
        if not user_tags:
            continue
        name = f"{domain}\\{user}" if domain else user
        members = []
        for tag_name, tag_timeout in user_tags:
            timeout_attr = f' timeout="{int(tag_timeout)}"' if tag_timeout is not None else ""
            members.append(f'<member{timeout_attr}>{xml_escape(tag_name)}</member>')
        if not members:
            continue
        register_entries.append(
            '<entry user="{user}"><tag>{members}</tag></entry>'.format(
                user=xml_escape(name), members="".join(members)
            )
        )

    payload_parts = ["<uid-message>", "<version>1.0</version>", "<type>update</type>", "<payload>"]
    if login_entries:
        payload_parts.append("<login>")
        payload_parts.append("".join(login_entries))
        payload_parts.append("</login>")
    if register_entries:
        payload_parts.append("<register-user>")
        payload_parts.append("".join(register_entries))
        payload_parts.append("</register-user>")
    payload_parts.append("</payload>")
    payload_parts.append("</uid-message>")
    return "".join(payload_parts)


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

    mac_to_ips: Dict[str, Set[str]] = defaultdict(set)

    arp_cache = parse_arp_cache()
    logging.info("Parsed ARP cache entries: %d", len(arp_cache))
    for mac, ip in arp_cache.items():
        mac_to_ips[mac].add(ip)

    ndp_cache = parse_ndp_cache()
    logging.info("Parsed NDP cache entries: %d", len(ndp_cache))
    for mac, ip in ndp_cache.items():
        mac_to_ips[mac].add(ip)

    iface_nets_v4 = get_directly_connected_ipv4_networks()
    if iface_nets_v4:
        logging.info("Discovered %d directly connected IPv4 networks", len(iface_nets_v4))
    else:
        logging.info("No directly connected IPv4 networks discovered; will rely on ARP cache only")

    iface_nets_v6 = get_directly_connected_ipv6_networks()
    if iface_nets_v6:
        logging.info("Discovered %d directly connected IPv6 networks", len(iface_nets_v6))
    else:
        logging.info("No directly connected IPv6 networks discovered; will rely on NDP cache only")

    # aggregate scan results
    for iface, net in iface_nets_v4:
        logging.info("Scanning IPv4 network %s on interface %s", net, iface)
        res = arp_scan_network(iface, net, timeout=scan_timeout)
        if res:
            logging.info("Found %d hosts in %s", len(res), net)
            for mac, ip in res.items():
                mac_to_ips[mac].add(ip)
        else:
            logging.debug("No hosts discovered in scan on %s (%s)", iface, net)

    for iface, net in iface_nets_v6:
        logging.info("Scanning IPv6 network %s on interface %s", net, iface)
        res = ndp_scan_network(iface, net, timeout=scan_timeout)
        if res:
            logging.info("Found %d IPv6 hosts in %s", len(res), net)
            for mac, ip in res.items():
                mac_to_ips[mac].add(ip)
        else:
            logging.debug("No IPv6 hosts discovered in scan on %s (%s)", iface, net)

    # build mappings list (username, ip) for all found IPs
    mappings: List[Tuple[str, str]] = []
    failures = []
    tag_map: Dict[str, List[Tuple[str, Optional[int]]]] = {}
    for user in data["users"]:
        user_id = user.get("id")
        macs = user.get("macs", []) or []
        if not user_id:
            logging.warning("Skipping entry without id")
            continue
        tags = parse_user_tags(user.get("tags"))
        if tags:
            tag_map.setdefault(user_id, []).extend(tags)
        for mac in macs:
            ips = find_ips_for_mac(mac, mac_to_ips)
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

    has_tags = any(tag_map.values())

    if not mappings and not has_tags:
        logging.info("No mappings or tags to send; exiting")
        return 0

    # build bulk payload (all login entries in one uid-message)
    payload = build_uid_payload(mappings, tag_map, timeout=entry_timeout, domain=domain)
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
