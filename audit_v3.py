#!/usr/bin/env python3
"""
CIS Benchmark — pfSense EXHAUSTIVE SECURITY AUDIT
Merged Sections:
  • Section 1 — General Settings
  • Section 2 — Users Management
  • Section 3 — Password Policy
  • Section 4 — Firewall Rules Policy
  • Section 5 — Infrastructure & VPN Security
  • Section 6 — Logging

PART 1 / 6
──────────────────────────────────────────────────────────────────────────────
Includes:
  • Imports
  • Display constants
  • Output helpers
  • Shared utility functions
  • Hash helpers
  • Version detection
  • XML extraction helpers
  • Firewall parser
  • VPN helpers
  • SNMP helpers
  • DNSSEC helpers
  • SYSLOG helpers
"""

import xml.etree.ElementTree as ET
import sys
import re
import base64
from datetime import datetime

from passlib.hash import (
    bcrypt as passlib_bcrypt,
    md5_crypt,
    sha256_crypt,
    sha512_crypt,
)

# ══════════════════════════════════════════════════════════════════════════════
# DISPLAY CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

W = 118

PASS   = "[ PASS ]"
FAIL   = "[ FAIL ]"
WARN   = "[ WARN ]"
INFO   = "[ INFO ]"
DETAIL = "[DETAIL]"
CRIT   = "[ CRIT ]"

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

STATUS_COLORS = {
    PASS:   C.GREEN,
    FAIL:   C.RED,
    WARN:   C.YELLOW,
    INFO:   C.CYAN,
    DETAIL: C.WHITE,
    CRIT:   C.MAGENTA,
}

RESET = C.RESET

# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD / ACCOUNT CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

BCRYPT_PREFIX   = "$2y$"
MIN_BCRYPT_COST = 10

DEFAULT_ACCOUNTS = {"admin"}

DEFAULT_PASSWORDS = [
    "pfsense",
    "admin",
    "password",
    "123456",
    "root",
    "toor",
    "changeme",
    "default",
    "firewall",
    "pfsense1",
]

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def line(char="─", width=W):
    print(char * width)

def banner(title: str):
    line("═")
    print(f"  {C.BOLD}{title}{C.RESET}")
    line("═")

def section(number: str, title: str):
    print()
    line("─")
    print(f"  {C.BOLD}CHECK {number} — {title}{C.RESET}")
    line("─")

def out(status: str, message: str, indent: int = 2):
    color = STATUS_COLORS.get(status, "")
    print(f"{' ' * indent}{color}{status}{C.RESET}  {message}")

def field(label: str, value: str, indent: int = 14):
    print(f"{' ' * indent}↳ {label:<38} {value}")

def blank():
    print()

def remediation(text: str):
    print(f"            ⚠  Remediation: {text}")

def reference(text: str):
    print(f"            ⚑  Reference:   {text}")

def risk(level: str):

    colors = {
        "LOW":      C.GREEN,
        "MEDIUM":   C.YELLOW,
        "HIGH":     C.RED,
        "CRITICAL": C.MAGENTA,
    }

    color = colors.get(level.upper(), C.WHITE)

    print(f"            {color}Risk Level : {level.upper()}{C.RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# SHARED UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def normalize(value: str) -> str:
    return (value or "").strip().upper()

def normalize_lower(value: str) -> str:
    return (value or "").strip().lower()

def is_enabled(value: str) -> bool:
    return normalize_lower(value) in (
        "yes",
        "on",
        "1",
        "true",
        "enabled"
    )

def safe_find_text(root, path):

    node = root.find(path)

    if node is not None and node.text:
        return node.text.strip()

    return None

def _bcrypt_cost(hash_str: str) -> int:

    try:
        return int(hash_str.split("$")[2])

    except (IndexError, ValueError):
        return -1

def _mask(secret: str, visible: int = 3) -> str:

    if not secret:
        return "(empty)"

    return (
        secret[:visible] + "*" * (len(secret) - visible)
        if len(secret) > visible
        else "*" * len(secret)
    )

def _decode_b64_keys(raw: str) -> list:

    try:

        decoded = base64.b64decode(
            raw
        ).decode(
            "utf-8",
            errors="replace"
        )

        return [
            k.strip()
            for k in decoded.strip().splitlines()
            if k.strip()
        ]

    except Exception:

        return [raw.strip()] if raw.strip() else []

def _key_type(key_line: str) -> str:

    parts = key_line.split()

    return parts[0] if parts else "unknown"

def _key_comment(key_line: str) -> str:

    parts = key_line.split()

    return parts[2] if len(parts) >= 3 else "(no comment)"

# ══════════════════════════════════════════════════════════════════════════════
# HASH DETECTION & PASSWORD VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def detect_hash_type(hash_value: str) -> str:

    if re.match(r'^\$2[abyx]?\$', hash_value):
        return "bcrypt"

    elif hash_value.startswith("$1$"):
        return "MD5 Crypt"

    elif hash_value.startswith("$5$"):
        return "SHA256 Crypt"

    elif hash_value.startswith("$6$"):
        return "SHA512 Crypt"

    return "Unknown"

def detect_bcrypt_variant(hash_value: str) -> str:

    for prefix in ("$2a$", "$2y$", "$2b$", "$2x$"):

        if hash_value.startswith(prefix):
            return prefix[1:3]

    return "Unknown"

def verify_password(password: str,
                    hash_value: str,
                    hash_type: str) -> bool:

    try:

        if hash_type == "bcrypt":
            return passlib_bcrypt.verify(password, hash_value)

        elif hash_type == "MD5 Crypt":
            return md5_crypt.verify(password, hash_value)

        elif hash_type == "SHA256 Crypt":
            return sha256_crypt.verify(password, hash_value)

        elif hash_type == "SHA512 Crypt":
            return sha512_crypt.verify(password, hash_value)

    except Exception:
        return False

    return False

def test_default_passwords(hash_value: str,
                           hash_type: str):

    for pwd in DEFAULT_PASSWORDS:

        if verify_password(
            pwd,
            hash_value,
            hash_type
        ):
            return pwd

    return None

# ══════════════════════════════════════════════════════════════════════════════
# VERSION DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def determine_pfsense_version(version: str):

    if not version:
        return ("Unknown", "Unknown")

    ce_versions = {
        "2.4": "pfSense CE 2.4.x",
        "2.5": "pfSense CE 2.5.x",
        "2.6": "pfSense CE 2.6.x",
        "2.7": "pfSense CE 2.7.x",
    }

    plus_versions = {
        "21": "pfSense Plus 21.x",
        "22": "pfSense Plus 22.x",
        "23": "pfSense Plus 23.x",
        "24": "pfSense Plus 24.x",
        "25": "pfSense Plus 25.x",
    }

    for prefix, name in ce_versions.items():

        if version.startswith(prefix):
            return (name, "Community Edition (CE)")

    for prefix, name in plus_versions.items():

        if version.startswith(prefix):
            return (name, "pfSense Plus")

    if version.startswith(("18.", "19.", "20.")):
        return (
            "Older Netgate/pfSense Build",
            "Legacy/Unknown"
        )

    return (
        "Unknown Version Family",
        "Unknown"
    )

# ══════════════════════════════════════════════════════════════════════════════
# USER EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def extract_users(root: ET.Element) -> list:

    users = []

    for user in root.findall(".//user"):

        username = (
            user.findtext("name", "") or ""
        ).strip()

        hash_value = (
            user.findtext("bcrypt-hash")
            or user.findtext("passwordhash")
            or user.findtext("md5-hash")
            or ""
        ).strip()

        password_field = (
            user.findtext("password")
            or ""
        ).strip()

        if not hash_value and password_field:

            detected = detect_hash_type(password_field)

            if detected != "Unknown":

                hash_value = password_field

        users.append({
            "username": username,
            "hash": hash_value,
            "disabled": user.find("disabled") is not None,
            "descr": user.findtext("descr", ""),
        })

    return users

# ══════════════════════════════════════════════════════════════════════════════
# FIREWALL RULE PARSER
# ══════════════════════════════════════════════════════════════════════════════

def get_firewall_rules(root: ET.Element):

    rules = []

    for rule in root.findall("./filter/rule"):

        parsed = {
            "type": rule.findtext("type", "").strip(),
            "interface": rule.findtext("interface", "").strip(),
            "descr": rule.findtext("descr", "").strip(),
            "source": "",
            "destination": "",
            "protocol": rule.findtext("protocol", "").strip(),
            "log": rule.find("log") is not None,
            "disabled": rule.find("disabled") is not None,
        }

        src = rule.find("./source")

        if src is not None:

            parsed["source"] = (
                src.findtext("address")
                or src.findtext("network")
                or src.findtext("any")
                or "unknown"
            )

        dst = rule.find("./destination")

        if dst is not None:

            parsed["destination"] = (
                dst.findtext("address")
                or dst.findtext("network")
                or dst.findtext("any")
                or "unknown"
            )

        rules.append(parsed)

    return rules

# ══════════════════════════════════════════════════════════════════════════════
# VPN HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def extract_custom_options(options, keyword):

    results = []

    if not options:
        return results

    for line_ in options.splitlines():

        if keyword in line_:

            parts = line_.split()

            if len(parts) > 1:

                results.extend(
                    re.split(
                        r"[:,]",
                        parts[1]
                    )
                )

    return [
        normalize(x)
        for x in results
        if x.strip()
    ]

def get_auth_servers(root):

    found = []

    found.extend(root.findall("./system/authserver"))
    found.extend(root.findall("./system/authservers/authserver"))
    found.extend(root.findall(".//authserver"))

    unique = []
    seen = set()

    for server in found:

        sid = id(server)

        if sid not in seen:

            seen.add(sid)
            unique.append(server)

    return unique

def get_openvpn_servers(root):

    found = []

    found.extend(root.findall("./openvpn/openvpn-server"))
    found.extend(root.findall(".//openvpn-server"))

    unique = []
    seen = set()

    for item in found:

        sid = id(item)

        if sid not in seen:

            seen.add(sid)
            unique.append(item)

    return unique

def get_certificates(root):

    found = []

    found.extend(root.findall("./cert"))
    found.extend(root.findall(".//cert"))

    unique = []
    seen = set()

    for cert in found:

        sid = id(cert)

        if sid not in seen:

            seen.add(sid)
            unique.append(cert)

    return unique

# ══════════════════════════════════════════════════════════════════════════════
# SNMP HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def find_native_snmp(root):

    snmp = root.find("snmpd")

    if snmp is not None:
        return snmp, "native <snmpd>"

    snmp = root.find("snmp")

    if snmp is not None:
        return snmp, "legacy <snmp>"

    return None, None

def find_net_snmp_package(root):

    for pkg in root.findall(".//installedpackages/package"):

        pkg_name = (
            pkg.findtext("name", "") or ""
        ).strip().lower()

        if pkg_name in (
            "net-snmp",
            "netsnmp",
            "net_snmp"
        ):
            return pkg

    return None

def get_trap_receivers(snmp):

    possible_tags = [
        "trapserver",
        "trap_receiver",
        "trapreceiver",
        "traphost",
        "receiver",
        "server"
    ]

    receivers = []

    for tag in possible_tags:

        for elem in snmp.findall(f".//{tag}"):

            value = (
                elem.text or ""
            ).strip()

            if value:
                receivers.append((tag, value))

    return receivers

def traps_enabled(snmp):

    possible_tags = [
        "enabletrap",
        "trapsenable",
        "enable_traps",
        "trapenable",
        "enable"
    ]

    for tag in possible_tags:

        value = (
            snmp.findtext(f".//{tag}", "") or ""
        ).strip().lower()

        if value in (
            "yes",
            "true",
            "on",
            "1",
            "enabled"
        ):
            return True, tag, value

    return False, None, None

# ══════════════════════════════════════════════════════════════════════════════
# DNSSEC HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_dnssec_status(root):

    unbound = root.find("unbound")

    if unbound is not None:

        possible_tags = [
            "enable_dnssec",
            "dnssec",
            "dnssecenable"
        ]

        for tag in possible_tags:

            value = (
                unbound.findtext(tag, "") or ""
            ).strip().lower()

            if value in (
                "yes",
                "true",
                "on",
                "1",
                "enabled"
            ):

                return (
                    True,
                    "DNS Resolver (Unbound)",
                    tag,
                    value
                )

        return (
            False,
            "DNS Resolver (Unbound)",
            None,
            None
        )

    dnsmasq = root.find("dnsmasq")

    if dnsmasq is not None:

        possible_tags = [
            "dnssec",
            "enable_dnssec",
            "dnssecenable"
        ]

        for tag in possible_tags:

            value = (
                dnsmasq.findtext(tag, "") or ""
            ).strip().lower()

            if value in (
                "yes",
                "true",
                "on",
                "1",
                "enabled"
            ):

                return (
                    True,
                    "DNS Forwarder (dnsmasq)",
                    tag,
                    value
                )

        return (
            False,
            "DNS Forwarder (dnsmasq)",
            None,
            None
        )

    return None, None, None, None

# ══════════════════════════════════════════════════════════════════════════════
# SYSLOG HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_syslog_config(root):
    """
    Locate syslog configuration.
    """

    return root.find("./syslog")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — GENERAL SETTING POLICY
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 1.1 SSH Warning Banner
# ─────────────────────────────────────────────────────────────────────────────

def check_1_1(root: ET.Element) -> bool:

    section("1.1", "Ensure SSH warning banner is configured")

    out(INFO,
        "Objective : Administrative SSH access should display a legal warning banner.")

    out(DETAIL,
        "Rationale : Warning banners help support legal enforcement and monitoring.")

    blank()

    ssh_enabled = root.find("./system/enablesshd")

    ssh_banner = (
        root.findtext("./system/sshguardmessage", "")
        or root.findtext("./system/sshbanner", "")
    )

    ssh_port = root.findtext("./system/sshport", "22")

    field("SSH Enabled",
          "YES" if ssh_enabled is not None else "NO")

    field("SSH Port", ssh_port)

    blank()

    if ssh_enabled is None:

        out(INFO, "SSH service appears disabled.")

        return True

    if ssh_banner and ssh_banner.strip():

        field("Banner Preview", ssh_banner[:100])

        blank()

        out(PASS, "SSH warning banner configured.")

        return True

    out(FAIL,
        "SSH enabled but no warning banner configured.")

    risk("MEDIUM")

    remediation(
        "Configure a legal warning banner for SSH administrative access."
    )

    reference(
        "CIS pfSense Benchmark — Section 1.1"
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 1.2 AutoConfigBackup
# ─────────────────────────────────────────────────────────────────────────────

def check_1_2(root: ET.Element) -> bool:

    section("1.2", "Ensure AutoConfigBackup is enabled")

    out(INFO,
        "Objective : Ensure pfSense configuration backups are enabled.")

    out(DETAIL,
        "Rationale : Backups help recover configurations after failure or compromise.")

    blank()

    acb = root.find("./installedpackages/autoconfigbackup")

    if acb is None:

        out(FAIL,
            "AutoConfigBackup package not installed.")

        risk("HIGH")

        remediation(
            "Install and enable AutoConfigBackup."
        )

        return False

    enable_acb = (
        acb.findtext("./config/enable_acb", "")
        or acb.findtext(".//enable", "")
    )

    username = acb.findtext("./config/username", "")

    device_key = (
        acb.findtext("./config/device_key", "")
        or acb.findtext(".//device_key", "")
    )

    crypto_password = acb.findtext(
        "./config/crypto_password",
        ""
    )

    field("AutoConfigBackup",
          enable_acb if enable_acb else "(not found)")

    field("Username",
          username if username else "(not found)")

    field("Device Key",
          "Present" if device_key else "Not Found")

    field("Backup Encryption",
          "Configured" if crypto_password else "Not Configured")

    blank()

    overall = True

    if is_enabled(enable_acb):

        out(PASS, "AutoConfigBackup is enabled.")

    else:

        out(FAIL, "AutoConfigBackup is disabled.")

        overall = False

    if crypto_password:

        out(PASS,
            "Backup encryption configured.")

    else:

        out(WARN,
            "No backup encryption password configured.")

        overall = False

    blank()

    if overall:

        out(PASS,
            "AutoConfigBackup appears securely configured.")

    else:

        out(WARN,
            "AutoConfigBackup configuration requires review.")

        risk("MEDIUM")

    return overall

# ─────────────────────────────────────────────────────────────────────────────
# 1.3 MOTD
# ─────────────────────────────────────────────────────────────────────────────

def check_1_3(root: ET.Element) -> bool:

    section("1.3",
            "Ensure Message Of The Day (MOTD) is set")

    out(INFO,
        "Objective : Administrative systems should display a login notice.")

    blank()

    motd = root.findtext("./system/motd", "")

    if motd and motd.strip():

        field("MOTD Preview", motd[:100])

        blank()

        out(PASS, "MOTD configured.")

        return True

    out(WARN, "MOTD not configured.")

    risk("LOW")

    remediation(
        "Configure a legal or administrative MOTD banner."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 1.4 Hostname
# ─────────────────────────────────────────────────────────────────────────────

def check_1_4(root: ET.Element) -> bool:

    section("1.4", "Ensure Hostname is set")

    out(INFO,
        "Objective : System hostname should be customized.")

    blank()

    hostname = root.findtext("./system/hostname", "")

    field("Hostname",
          hostname if hostname else "(not found)")

    blank()

    if not hostname:

        out(CRIT, "Hostname missing.")

        risk("HIGH")

        return False

    if hostname.lower() == "pfsense":

        out(WARN,
            "Default hostname still used.")

        risk("LOW")

        remediation(
            "Configure a unique hostname."
        )

        return False

    out(PASS, "Custom hostname configured.")

    return True

# ─────────────────────────────────────────────────────────────────────────────
# 1.5 DNS Servers
# ─────────────────────────────────────────────────────────────────────────────

def check_1_5(root: ET.Element) -> bool:

    section("1.5",
            "Ensure DNS server is configured")

    out(INFO,
        "Objective : DNS resolvers should be explicitly configured.")

    blank()

    dns_servers = []

    for tag in root.findall("./system/dnsserver"):

        if tag.text:
            dns_servers.append(tag.text)

    for i in range(1, 5):

        dns = root.findtext(
            f"./system/dnsserver{i}",
            ""
        )

        if dns and dns not in dns_servers:
            dns_servers.append(dns)

    if dns_servers:

        field("DNS Servers Found",
              str(len(dns_servers)))

        blank()

        for idx, dns in enumerate(dns_servers, 1):

            field(f"DNS Server #{idx}", dns)

        blank()

        out(PASS, "DNS servers configured.")

        return True

    out(FAIL, "No DNS servers configured.")

    risk("HIGH")

    remediation(
        "Configure trusted DNS resolvers."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 1.6 IPv6
# ─────────────────────────────────────────────────────────────────────────────

def check_1_6(root: ET.Element) -> bool:

    section("1.6",
            "Ensure IPv6 is disabled if not used")

    out(INFO,
        "Objective : Disable IPv6 when not operationally required.")

    blank()

    ipv6_found = False

    for interface in root.findall("./interfaces/*"):

        interface_name = interface.tag

        ipv6 = interface.findtext("ipaddrv6", "")

        if ipv6 and ipv6.strip():

            ipv6_found = True

            field(
                f"IPv6 Interface ({interface_name})",
                ipv6
            )

    blank()

    if ipv6_found:

        out(WARN,
            "IPv6 configuration detected.")

        risk("MEDIUM")

        remediation(
            "Disable IPv6 on unused interfaces."
        )

        return False

    out(PASS, "IPv6 appears disabled.")

    return True

# ─────────────────────────────────────────────────────────────────────────────
# 1.7 DNS Rebind Check
# ─────────────────────────────────────────────────────────────────────────────

def check_1_7(root: ET.Element) -> bool:

    section("1.7",
            "Ensure DNS Rebind Check is unchecked")

    out(INFO,
        "Objective : DNS rebinding protection should remain enabled.")

    blank()

    rebind_disabled = root.find(
        "./system/dnsrebindcheck"
    )

    if rebind_disabled is not None:

        out(FAIL,
            "'Disable DNS Rebinding Checks' is CHECKED.")

        risk("HIGH")

        remediation(
            "Remove <dnsrebindcheck> or disable the option."
        )

        overall = False

    else:

        out(PASS,
            "'Disable DNS Rebinding Checks' is UNCHECKED.")

        overall = True

    blank()

    return overall

# ─────────────────────────────────────────────────────────────────────────────
# 1.8 WebGUI HTTPS
# ─────────────────────────────────────────────────────────────────────────────

def check_1_8(root: ET.Element) -> bool:

    section("1.8",
            "Ensure Web Management is set to use HTTPS")

    out(INFO,
        "Objective : Web administration must use HTTPS.")

    blank()

    protocol = root.findtext(
        "./system/webgui/protocol",
        ""
    )

    port = root.findtext(
        "./system/webgui/port",
        ""
    )

    field("Protocol",
          protocol if protocol else "(default)")

    field("Port",
          port if port else "(default)")

    blank()

    if protocol.lower() == "https":

        out(PASS, "WebGUI uses HTTPS.")

        return True

    elif protocol.lower() == "http":

        out(CRIT,
            "WebGUI uses insecure HTTP.")

        risk("CRITICAL")

        remediation(
            "Switch WebGUI management to HTTPS."
        )

        return False

    out(WARN,
        "Protocol not explicitly defined.")

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 1.9 High Availability
# ─────────────────────────────────────────────────────────────────────────────

def check_1_9(root: ET.Element) -> bool:

    section(
        "1.9",
        "Ensure a synchronized High Availability peer is configured"
    )

    out(INFO,
        "Objective : High Availability synchronization should be configured.")

    blank()

    hasync = root.find("./hasync")

    if hasync is None:

        out(FAIL,
            "No <hasync> block found.")

        risk("HIGH")

        remediation(
            "Configure High Availability synchronization."
        )

        return False

    pfsync_enabled = hasync.findtext(
        "pfsyncenabled",
        ""
    ).strip()

    pfsync_interface = hasync.findtext(
        "pfsyncinterface",
        ""
    ).strip()

    pfsync_peerip = hasync.findtext(
        "pfsyncpeerip",
        ""
    ).strip()

    sync_target_ip = hasync.findtext(
        "synchronizetoip",
        ""
    ).strip()

    username = hasync.findtext(
        "username",
        ""
    ).strip()

    password = hasync.findtext(
        "password",
        ""
    ).strip()

    field("pfsync Enabled",
          pfsync_enabled if pfsync_enabled else "Not Found")

    field("pfsync Interface",
          pfsync_interface if pfsync_interface else "Not Found")

    field("pfsync Peer IP",
          pfsync_peerip if pfsync_peerip else "Not Found")

    field("Sync Target IP",
          sync_target_ip if sync_target_ip else "Not Found")

    field("Sync Username",
          username if username else "Not Found")

    blank()

    overall = True

    if pfsync_enabled.lower() == "on" and pfsync_peerip:

        out(PASS,
            "pfsync enabled with peer synchronization.")

    else:

        out(FAIL,
            "pfsync synchronization incomplete.")

        overall = False

    if pfsync_interface:

        out(PASS,
            "Dedicated synchronization interface configured.")

    else:

        out(WARN,
            "No dedicated synchronization interface configured.")

        overall = False

    if sync_target_ip:

        out(PASS,
            "XMLRPC synchronization configured.")

    else:

        out(WARN,
            "XMLRPC synchronization target missing.")

        overall = False

    if password:

        if len(password) < 12:

            out(WARN,
                "Synchronization password may be weak (<12 chars).")

            overall = False

        else:

            out(PASS,
                "Synchronization password length acceptable.")

    else:

        out(WARN,
            "Synchronization password not found.")

        overall = False

    blank()

    if overall:

        out(PASS,
            "High Availability synchronization appears secure.")

    else:

        out(WARN,
            "High Availability configuration requires review.")

        risk("MEDIUM")

    return overall

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — USERS MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 2.1 Session Timeout
# ─────────────────────────────────────────────────────────────────────────────

def check_2_1_session_timeout(root: ET.Element) -> bool:

    section(
        "2.1",
        "Ensure Session Timeout is set to ≤ 10 Minutes"
    )

    out(
        INFO,
        "Objective  : The GUI session must automatically expire after at most 10 minutes"
    )

    out(
        INFO,
        "             of inactivity to prevent unauthorized access from unattended browsers."
    )

    out(
        DETAIL,
        "Rationale  : Long or infinite sessions increase the attack window if a privileged"
    )

    out(
        DETAIL,
        "             browser tab is left open on a shared or unattended workstation."
    )

    blank()

    timeout_str = None
    source_xpath = None

    webgui_node = root.find("./system/webgui")

    if webgui_node is not None:

        timeout_str = webgui_node.findtext(
            "session_timeout"
        )

        source_xpath = "./system/webgui/session_timeout"

    if timeout_str is None:

        system_node = root.find("./system")

        if system_node is not None:

            timeout_str = system_node.findtext(
                "session_timeout"
            )

            source_xpath = "./system/session_timeout"

    out(DETAIL, "XML inspection:")

    field(
        "XPath checked (new, pfSense 2.5+)",
        "./system/webgui/session_timeout"
    )

    field(
        "XPath checked (legacy)",
        "./system/session_timeout"
    )

    field(
        "Value found at",
        source_xpath if source_xpath else "not present"
    )

    field(
        "Raw XML value",
        f"'{timeout_str}'" if timeout_str is not None else "(tag absent)"
    )

    blank()

    if timeout_str is None:

        out(
            FAIL,
            "Session timeout tag is ABSENT from config.xml."
        )

        remediation(
            "Configure Session Timeout to ≤ 10 minutes."
        )

        return False

    try:

        timeout = int(timeout_str)

    except ValueError:

        out(
            FAIL,
            f"Session timeout value '{timeout_str}' is not a valid integer."
        )

        return False

    field(
        "Parsed timeout",
        f"{timeout} minute(s)"
    )

    field(
        "Maximum allowed",
        "10 minutes"
    )

    blank()

    if timeout == 0:

        out(
            FAIL,
            "Timeout is explicitly set to 0 — sessions NEVER expire automatically."
        )

        remediation(
            "Set a positive timeout ≤ 10 minutes."
        )

        return False

    if timeout < 0:

        out(
            FAIL,
            f"Timeout value {timeout} is invalid."
        )

        return False

    if timeout <= 10:

        out(
            PASS,
            f"Session timeout = {timeout} minute(s) — COMPLIANT."
        )

        return True

    out(
        FAIL,
        f"Session timeout = {timeout} minutes — exceeds 10-minute maximum."
    )

    remediation(
        "Lower Session Timeout to ≤ 10 minutes."
    )

    return False


# ─────────────────────────────────────────────────────────────────────────────
# 2.2 LDAP or RADIUS
# ─────────────────────────────────────────────────────────────────────────────

def check_2_2_external_auth(root: ET.Element) -> bool:

    section(
        "2.2",
        "Ensure LDAP or RADIUS Server is Configured"
    )

    out(
        INFO,
        "Objective  : At least one LDAP or RADIUS authentication server must exist."
    )

    out(
        DETAIL,
        "Rationale  : Centralized authentication improves governance and auditing."
    )

    blank()

    authservers = root.findall("./system/authserver")

    out(
        DETAIL,
        f"Total <authserver> entries found in config.xml: {len(authservers)}"
    )

    blank()

    ldap_servers = []
    radius_servers = []

    for auth in authservers:

        atype = auth.findtext(
            "type",
            ""
        ).strip().lower()

        if "ldap" in atype:

            ldap_servers.append(auth)

        elif "radius" in atype:

            radius_servers.append(auth)

    if ldap_servers:

        out(
            PASS,
            f"{len(ldap_servers)} LDAP server(s) found."
        )

        for idx, server in enumerate(ldap_servers, 1):

            field("LDAP Server", f"#{idx}")

            field(
                "Name",
                server.findtext("name", "Unknown")
            )

            field(
                "Host",
                server.findtext("host", "(not set)")
            )

            blank()

    if radius_servers:

        out(
            PASS,
            f"{len(radius_servers)} RADIUS server(s) found."
        )

        for idx, server in enumerate(radius_servers, 1):

            field("RADIUS Server", f"#{idx}")

            field(
                "Name",
                server.findtext("name", "Unknown")
            )

            field(
                "Host",
                server.findtext("host", "(not set)")
            )

            blank()

    if not ldap_servers and not radius_servers:

        out(
            FAIL,
            "NO LDAP or RADIUS authentication server is configured."
        )

        remediation(
            "Configure centralized authentication."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 2.2"
        )

        return False

    return True

# ─────────────────────────────────────────────────────────────────────────────
# 2.3 Console Password Protection
# ─────────────────────────────────────────────────────────────────────────────

def check_2_3_console_password(root: ET.Element) -> bool:

    section(
        "2.3",
        "Ensure Console Menu is Password Protected"
    )

    out(
        INFO,
        "Objective  : The physical/serial console must require credentials."
    )

    out(
        DETAIL,
        "Rationale  : An unprotected console allows bypass of authentication."
    )

    blank()

    new_tag_val = root.findtext(
        "./system/console/password_protected",
        ""
    )

    old_tag = root.find(
        "./system/disableconsolemenu"
    )

    out(DETAIL, "XML inspection:")

    field(
        "XPath (pfSense 2.5+)",
        "./system/console/password_protected"
    )

    field(
        "Value found",
        f"'{new_tag_val}'" if new_tag_val else "(tag absent)"
    )

    field(
        "XPath (legacy ≤2.4)",
        "./system/disableconsolemenu"
    )

    field(
        "Tag present",
        "YES" if old_tag is not None else "NO"
    )

    blank()

    if new_tag_val.lower() in (
        "enabled",
        "1",
        "true",
        "yes"
    ):

        out(
            PASS,
            "Console password protection is enabled."
        )

        return True

    if old_tag is not None:

        out(
            FAIL,
            "Legacy <disableconsolemenu> tag detected — protection disabled."
        )

        remediation(
            "Enable console password protection in System > Advanced."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 2.3"
        )

        return False

    out(
        PASS,
        "Console password protection is ACTIVE."
    )

    return True

# ─────────────────────────────────────────────────────────────────────────────
# 2.4 Default Accounts
# ─────────────────────────────────────────────────────────────────────────────

def check_2_4_default_accounts(root: ET.Element) -> bool:

    section(
        "2.4",
        "Ensure All Default Accounts Are Disabled or Use Strong Passwords"
    )

    out(
        INFO,
        "Objective  : Built-in default accounts must be disabled or secured."
    )

    out(
        DETAIL,
        "Rationale  : Default accounts are universally targeted by attackers."
    )

    blank()

    users = root.findall("./system/user")

    out(
        DETAIL,
        f"Total local accounts in config.xml: {len(users)}"
    )

    blank()

    overall = True
    default_found = False

    for user in users:

        username = user.findtext("name", "")

        if username.lower() not in DEFAULT_ACCOUNTS:
            continue

        default_found = True

        blank()

        line("┄")

        out(
            DETAIL,
            f"Deep evaluation of default account: '{username}'"
        )

        line("┄")

        blank()

        disabled = user.find("disabled")

        bcrypt_hash = user.findtext(
            "bcrypt-hash",
            ""
        )

        legacy_pw = user.findtext(
            "password",
            ""
        )

        field("Username", username)

        field(
            "Status",
            "DISABLED" if disabled is not None else "ACTIVE"
        )

        blank()

        if disabled is not None:

            out(
                PASS,
                f"'{username}' is DISABLED."
            )

            continue

        out(
            WARN,
            f"'{username}' is ACTIVE — evaluating password security."
        )

        blank()

        if legacy_pw:

            out(
                CRIT,
                f"CRITICAL: '{username}' uses legacy <password> storage."
            )

            remediation(
                "Reset password to force bcrypt hashing."
            )

            overall = False

            continue

        if not bcrypt_hash:

            out(
                CRIT,
                f"CRITICAL: '{username}' has NO password hash."
            )

            overall = False

            continue

        hash_type = detect_hash_type(bcrypt_hash)

        field("Hash algorithm", hash_type)

        field(
            "Hash preview",
            bcrypt_hash[:20] + "…"
        )

        blank()

        if hash_type == "bcrypt":

            variant = detect_bcrypt_variant(bcrypt_hash)

            cost = _bcrypt_cost(bcrypt_hash)

            field(
                "bcrypt variant",
                f"${variant}$"
            )

            field(
                "bcrypt cost factor",
                str(cost)
            )

            blank()

            if cost < MIN_BCRYPT_COST:

                out(
                    FAIL,
                    f"bcrypt cost factor {cost} is BELOW minimum {MIN_BCRYPT_COST}."
                )

                overall = False

            else:

                out(
                    PASS,
                    f"bcrypt cost factor = {cost} — COMPLIANT."
                )

        else:

            out(
                WARN,
                f"Hash type is {hash_type} — not bcrypt."
            )

            overall = False

        blank()

        out(
            DETAIL,
            f"Default password scan ({len(DEFAULT_PASSWORDS)} passwords tested):"
        )

        matched_pwd = test_default_passwords(
            bcrypt_hash,
            hash_type
        )

        if matched_pwd:

            out(
                CRIT,
                f"DEFAULT PASSWORD DETECTED — matches '{matched_pwd}'"
            )

            remediation(
                f"Change password for '{username}' immediately."
            )

            overall = False

        else:

            out(
                PASS,
                "Password does not match tested defaults."
            )

        blank()

    if not default_found:

        out(
            PASS,
            f"No accounts matching {DEFAULT_ACCOUNTS} were found."
        )

    if not overall:

        reference(
            "CIS pfSense Benchmark v1.0 — Section 2.4"
        )

    return overall

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — PASSWORD POLICY
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 3.1 Local Account Status
# ─────────────────────────────────────────────────────────────────────────────

def check_3_1(root: ET.Element) -> bool:

    section(
        "3.1",
        "Ensure Local Account Status is set to Disabled"
    )

    users = extract_users(root)

    active = [
        u for u in users
        if not u["disabled"]
    ]

    disabled = [
        u for u in users
        if u["disabled"]
    ]

    field("Total Accounts", str(len(users)))
    field("Active Accounts", str(len(active)))
    field("Disabled Accounts", str(len(disabled)))

    blank()

    if len(active) == 0:

        out(
            FAIL,
            "No active local accounts detected."
        )

        remediation(
            "At least one administrative account is required."
        )

        return False

    if len(active) <= 3:

        out(
            PASS,
            "Local account configuration appears reasonable."
        )

        return True

    out(
        WARN,
        f"{len(active)} active accounts detected."
    )

    remediation(
        "Disable unnecessary or unused accounts."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 3.2 Login Protection Threshold
# ─────────────────────────────────────────────────────────────────────────────

def check_3_2(root: ET.Element) -> bool:

    section(
        "3.2",
        "Ensure Login Protection Threshold is set to 30 or less"
    )

    threshold = (
        root.findtext("./system/sshguard_threshold")
        or root.findtext("./system/webgui/sshguard_threshold")
    )

    if threshold is None:

        out(
            FAIL,
            "Login protection threshold not configured."
        )

        return False

    field("Threshold", threshold)

    blank()

    try:

        value = int(threshold)

    except ValueError:

        out(
            FAIL,
            "Invalid threshold value."
        )

        return False

    if value <= 30:

        out(
            PASS,
            f"Threshold = {value} (compliant)"
        )

        if value <= 10:

            out(
                INFO,
                "Excellent security posture."
            )

        return True

    out(
        FAIL,
        f"Threshold = {value} exceeds 30."
    )

    remediation(
        "Reduce threshold to ≤ 30."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 3.3 Lockout Duration
# ─────────────────────────────────────────────────────────────────────────────

def check_3_3(root: ET.Element) -> bool:

    section(
        "3.3",
        "Ensure Allow Access Again After is set to 300s or more"
    )

    blocktime = (
        root.findtext("./system/sshguard_blocktime")
        or root.findtext("./system/webgui/sshguard_blocktime")
    )

    if blocktime is None:

        out(
            FAIL,
            "Lockout duration not configured."
        )

        return False

    field(
        "Lockout Duration",
        f"{blocktime} seconds"
    )

    blank()

    try:

        value = int(blocktime)

    except ValueError:

        out(
            FAIL,
            "Invalid lockout duration."
        )

        return False

    if value >= 300:

        out(
            PASS,
            f"Lockout duration = {value}s (compliant)"
        )

        return True

    out(
        FAIL,
        f"Lockout duration = {value}s is too low."
    )

    remediation(
        "Set value ≥ 300 seconds."
    )

    return False


# ─────────────────────────────────────────────────────────────────────────────
# 3.4 Default Passwords
# ─────────────────────────────────────────────────────────────────────────────

def check_3_4(root: ET.Element) -> bool:

    section(
        "3.4",
        "Ensure Default Passwords Are Changed"
    )

    out(
        INFO,
        "Objective : Detect default or weak passwords across ALL local accounts."
    )

    out(
        INFO,
        f"            Tests each hash against {len(DEFAULT_PASSWORDS)} known passwords."
    )

    blank()

    users = extract_users(root)

    if not users:

        out(
            FAIL,
            "No users found."
        )

        return False

    secure = True

    for idx, user in enumerate(users, 1):

        username = user["username"]
        hash_value = user["hash"]

        line("┄")

        out(
            DETAIL,
            f"User #{idx} Password Review"
        )

        line("┄")

        blank()

        field("Username", username)

        field(
            "Status",
            "DISABLED" if user["disabled"] else "ACTIVE"
        )

        blank()

        if not hash_value:

            out(
                CRIT,
                "No password hash found."
            )

            secure = False

            blank()

            continue

        hash_type = detect_hash_type(hash_value)

        field("Hash Type", hash_type)

        if hash_type == "bcrypt":

            field(
                "bcrypt Variant",
                detect_bcrypt_variant(hash_value)
            )

        field(
            "Hash (preview)",
            hash_value[:70] + "…"
        )

        blank()

        if hash_type == "Unknown":

            out(
                WARN,
                "Unknown hash type — cannot verify password."
            )

            secure = False

            blank()

            continue

        matched = test_default_passwords(
            hash_value,
            hash_type
        )

        if matched:

            out(
                FAIL,
                f"Default password detected: '{matched}'"
            )

            remediation(
                f"Change password immediately for user '{username}'."
            )

            secure = False

        else:

            out(
                PASS,
                "Password does not match any known defaults."
            )

        blank()

    return secure

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — FIREWALL RULES POLICY
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 4.1.1 No Allow Rule with Any Destination
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_1_any_destination(root: ET.Element) -> bool:

    section(
        "4.1.1",
        "Ensure no Allow Rule with Any in Destination Field"
    )

    out(
        INFO,
        "Objective  : No PASS rule should allow traffic to destination 'any'."
    )

    out(
        INFO,
        "             Destination must be explicitly restricted whenever possible."
    )

    out(
        DETAIL,
        "Rationale  : 'Allow → Any Destination' creates excessive trust boundaries."
    )

    out(
        DETAIL,
        "             It permits unrestricted lateral movement and outbound access."
    )

    blank()

    rules = get_firewall_rules(root)

    field(
        "Total firewall rules",
        str(len(rules))
    )

    blank()

    findings = []
    overall = True

    line("┄")

    out(DETAIL, "Per-rule inspection")

    line("┄")

    blank()

    for idx, rule in enumerate(rules, 1):

        if rule["disabled"]:
            continue

        if rule["type"].lower() != "pass":
            continue

        destination = str(
            rule["destination"]
        ).lower()

        field("Rule", f"#{idx}")

        field(
            "Description",
            rule["descr"] or "(none)"
        )

        field(
            "Interface",
            rule["interface"] or "(none)"
        )

        field("Type", rule["type"])

        field(
            "Destination",
            rule["destination"]
        )

        field(
            "Protocol",
            rule["protocol"] or "any"
        )

        blank()

        if destination in ("any", "", "unknown"):

            out(
                FAIL,
                "Allow rule uses destination = ANY"
            )

            out(
                DETAIL,
                "This creates broad unrestricted access."
            )

            findings.append(rule)

            overall = False

        else:

            out(
                PASS,
                "Destination is explicitly restricted."
            )

        blank()

    if findings:

        line("┄")

        out(
            FAIL,
            f"{len(findings)} risky allow rule(s) found using destination ANY."
        )

        remediation(
            "Replace destination 'any' with specific hosts, networks, or aliases."
        )

        remediation(
            "Use least privilege segmentation for internal and outbound traffic."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 4.1.1"
        )

    else:

        out(
            PASS,
            "No allow rules with destination ANY were found."
        )

    return overall

# ─────────────────────────────────────────────────────────────────────────────
# 4.1.2 No Allow Rule with Any Source
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_2_any_source(root: ET.Element) -> bool:

    section(
        "4.1.2",
        "Ensure no Allow Rule with Any in Source Field"
    )

    out(
        INFO,
        "Objective  : No PASS rule should allow traffic from source 'any'."
    )

    out(
        INFO,
        "             Source must be explicitly restricted whenever possible."
    )

    out(
        DETAIL,
        "Rationale  : 'Allow from Any Source' permits unknown/untrusted origins."
    )

    blank()

    rules = get_firewall_rules(root)

    field(
        "Total firewall rules",
        str(len(rules))
    )

    blank()

    findings = []
    overall = True

    line("┄")

    out(DETAIL, "Per-rule inspection")

    line("┄")

    blank()

    for idx, rule in enumerate(rules, 1):

        if rule["disabled"]:
            continue

        if rule["type"].lower() != "pass":
            continue

        source = str(
            rule["source"]
        ).lower()

        field("Rule", f"#{idx}")

        field(
            "Description",
            rule["descr"] or "(none)"
        )

        field(
            "Interface",
            rule["interface"] or "(none)"
        )

        field("Type", rule["type"])

        field(
            "Source",
            rule["source"]
        )

        field(
            "Protocol",
            rule["protocol"] or "any"
        )

        blank()

        if source in ("any", "", "unknown"):

            out(
                FAIL,
                "Allow rule uses source = ANY"
            )

            out(
                DETAIL,
                "This permits unrestricted origin access."
            )

            findings.append(rule)

            overall = False

        else:

            out(
                PASS,
                "Source is explicitly restricted."
            )

        blank()

    if findings:

        line("┄")

        out(
            FAIL,
            f"{len(findings)} risky allow rule(s) found using source ANY."
        )

        remediation(
            "Replace source 'any' with specific trusted networks or hosts."
        )

        remediation(
            "Use aliases to define approved administrative or application sources."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 4.1.2"
        )

    else:

        out(
            PASS,
            "No allow rules with source ANY were found."
        )

    return overall

# ─────────────────────────────────────────────────────────────────────────────
# 4.1.3 No Allow Rule with Any Service
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_3_any_service(root: ET.Element) -> bool:

    section(
        "4.1.3",
        "Ensure no Allow Rule with Any in Services Field"
    )

    out(
        INFO,
        "Objective  : PASS rules must not allow service/protocol = ANY."
    )

    out(
        DETAIL,
        "Rationale  : Allowing ANY service exposes all ports and protocols."
    )

    blank()

    rules = get_firewall_rules(root)

    field(
        "Total firewall rules",
        str(len(rules))
    )

    blank()

    findings = []
    overall = True

    line("┄")

    out(DETAIL, "Per-rule inspection")

    line("┄")

    blank()

    for idx, rule in enumerate(rules, 1):

        if rule["disabled"]:
            continue

        if rule["type"].lower() != "pass":
            continue

        protocol = str(
            rule["protocol"]
        ).lower()

        field("Rule", f"#{idx}")

        field(
            "Description",
            rule["descr"] or "(none)"
        )

        field(
            "Interface",
            rule["interface"] or "(none)"
        )

        field(
            "Source",
            rule["source"] or "(none)"
        )

        field(
            "Destination",
            rule["destination"] or "(none)"
        )

        field(
            "Protocol/Service",
            rule["protocol"] or "any"
        )

        blank()

        if protocol in ("", "any"):

            out(
                FAIL,
                "Allow rule uses service/protocol = ANY"
            )

            findings.append(rule)

            overall = False

        else:

            out(
                PASS,
                "Service is explicitly restricted."
            )

        blank()

    if findings:

        line("┄")

        out(
            FAIL,
            f"{len(findings)} risky allow rule(s) found using ANY service."
        )

        remediation(
            "Replace protocol 'any' with explicit services only."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 4.1.3"
        )

    else:

        out(
            PASS,
            "No allow rules with ANY service were found."
        )

    return overall

# ─────────────────────────────────────────────────────────────────────────────
# 4.1.4 Unused Policies
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_4_unused_policies(root: ET.Element) -> bool:

    section(
        "4.1.4",
        "Ensure there are no Unused Policies"
    )

    out(
        INFO,
        "Objective  : Firewall policies must be actively used and justified."
    )

    out(
        DETAIL,
        "Rationale  : Stale or obsolete firewall rules create hidden risk."
    )

    blank()

    rules = get_firewall_rules(root)

    field(
        "Total firewall rules",
        str(len(rules))
    )

    blank()

    findings = []
    overall = True

    suspicious_keywords = [
        "temp",
        "temporary",
        "test",
        "old",
        "legacy",
        "migration",
        "debug",
        "troubleshoot",
        "unused",
        "backup"
    ]

    line("┄")

    out(
        DETAIL,
        "Heuristic review of potentially unused policies"
    )

    line("┄")

    blank()

    for idx, rule in enumerate(rules, 1):

        descr = (rule["descr"] or "").lower()

        field("Rule", f"#{idx}")

        field(
            "Description",
            rule["descr"] or "(none)"
        )

        field(
            "Interface",
            rule["interface"] or "(none)"
        )

        field(
            "Status",
            "DISABLED" if rule["disabled"] else "ACTIVE"
        )

        field(
            "Type",
            rule["type"] or "(none)"
        )

        blank()

        suspicious = False

        if rule["disabled"]:

            out(
                WARN,
                "Rule is disabled — possible obsolete policy."
            )

            suspicious = True

        if not rule["descr"].strip():

            out(
                WARN,
                "Rule has no description."
            )

            suspicious = True

        for keyword in suspicious_keywords:

            if keyword in descr:

                out(
                    WARN,
                    f"Description contains suspicious keyword: '{keyword}'"
                )

                suspicious = True

                break

        if suspicious:

            findings.append(rule)

            overall = False

        else:

            out(
                PASS,
                "No obvious stale/unused indicators detected."
            )

        blank()

    if findings:

        line("┄")

        out(
            WARN,
            f"{len(findings)} rule(s) require manual review."
        )

        remediation(
            "Review logs and remove obsolete or temporary rules."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 4.1.4"
        )

    else:

        out(
            PASS,
            "No obvious unused policies detected."
        )

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.5 Logging Enabled
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_5_rule_logging(root: ET.Element) -> bool:

    section(
        "4.1.5",
        "Ensure Logging is Enabled for All Firewall Rules"
    )

    out(
        INFO,
        "Objective  : Security-relevant firewall rules must have logging enabled."
    )

    out(
        INFO,
        "             Logs must provide visibility for monitoring and investigations."
    )

    out(
        DETAIL,
        "Rationale  : Without firewall logging, attacks may remain invisible."
    )

    out(
        DETAIL,
        "             There will be no evidence showing which rule allowed"
    )

    out(
        DETAIL,
        "             suspicious traffic or unauthorized access attempts."
    )

    blank()

    rules = get_firewall_rules(root)

    field(
        "Total firewall rules",
        str(len(rules))
    )

    blank()

    findings = []
    overall = True

    line("┄")

    out(
        DETAIL,
        "Per-rule logging inspection"
    )

    line("┄")

    blank()

    for idx, rule in enumerate(rules, 1):

        if rule["disabled"]:
            continue

        field("Rule", f"#{idx}")

        field(
            "Description",
            rule["descr"] or "(none)"
        )

        field(
            "Interface",
            rule["interface"] or "(none)"
        )

        field(
            "Type",
            rule["type"] or "(none)"
        )

        field(
            "Source",
            rule["source"] or "(none)"
        )

        field(
            "Destination",
            rule["destination"] or "(none)"
        )

        field(
            "Logging",
            "ENABLED" if rule["log"] else "DISABLED"
        )

        blank()

        if not rule["log"]:

            out(
                WARN,
                "Logging is disabled for this rule."
            )

            out(
                DETAIL,
                "This reduces visibility and weakens forensic capability."
            )

            findings.append(rule)

            overall = False

        else:

            out(
                PASS,
                "Logging is enabled."
            )

        blank()

    if findings:

        line("┄")

        out(
            WARN,
            f"{len(findings)} rule(s) found without logging enabled."
        )

        remediation(
            "Enable 'Log packets handled by this rule' for critical rules."
        )

        remediation(
            "Prioritize WAN rules, PASS rules, admin access, and VPN policies."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 4.1.5"
        )

    else:

        out(
            PASS,
            "Logging is enabled for all active rules."
        )

    return overall

# ─────────────────────────────────────────────────────────────────────────────
# 4.1.6 ICMP Security
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_6_icmp_security(root: ET.Element) -> bool:

    section(
        "4.1.6",
        "Ensure ICMP Request is Securely Configured"
    )

    out(
        INFO,
        "Objective  : ICMP must be restricted to legitimate operational needs only."
    )

    out(
        INFO,
        "             Broad ICMP allow rules should be avoided."
    )

    out(
        DETAIL,
        "Rationale  : ICMP is useful for diagnostics (ping, traceroute),"
    )

    out(
        DETAIL,
        "             but unrestricted ICMP increases reconnaissance exposure."
    )

    blank()

    rules = get_firewall_rules(root)

    field(
        "Total firewall rules",
        str(len(rules))
    )

    blank()

    findings = []
    overall = True

    line("┄")

    out(DETAIL, "ICMP rule inspection")

    line("┄")

    blank()

    for idx, rule in enumerate(rules, 1):

        if rule["disabled"]:
            continue

        protocol = str(
            rule["protocol"]
        ).lower()

        if protocol != "icmp":
            continue

        field("Rule", f"#{idx}")

        field(
            "Description",
            rule["descr"] or "(none)"
        )

        field(
            "Interface",
            rule["interface"] or "(none)"
        )

        field(
            "Type",
            rule["type"] or "(none)"
        )

        field(
            "Source",
            rule["source"] or "(none)"
        )

        field(
            "Destination",
            rule["destination"] or "(none)"
        )

        field(
            "Protocol",
            rule["protocol"]
        )

        blank()

        risky = False

        if rule["type"].lower() == "pass":

            if str(rule["source"]).lower() in (
                "any",
                "",
                "unknown"
            ):

                out(
                    WARN,
                    "ICMP allowed from ANY source."
                )

                risky = True

            if str(rule["destination"]).lower() in (
                "any",
                "",
                "unknown"
            ):

                out(
                    WARN,
                    "ICMP allowed to ANY destination."
                )

                risky = True

            if risky:

                out(
                    DETAIL,
                    "Broad ICMP exposure detected — review necessity."
                )

                findings.append(rule)

                overall = False

            else:

                out(
                    PASS,
                    "ICMP rule appears reasonably restricted."
                )

        blank()

    if findings:

        line("┄")

        out(
            WARN,
            f"{len(findings)} risky ICMP rule(s) require review."
        )

        remediation(
            "Restrict ICMP to trusted monitoring or management networks only."
        )

        remediation(
            "Avoid allowing ICMP from Internet/WAN unless explicitly justified."
        )

        reference(
            "CIS pfSense Benchmark v1.0 — Section 4.1.6"
        )

    else:

        out(
            PASS,
            "No risky ICMP configurations detected."
        )

    return overall

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — INFRASTRUCTURE & VPN SECURITY
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 5.1.1 SNMP Trap Receivers
# ─────────────────────────────────────────────────────────────────────────────

def check_5_1_1(root):

    section(
        "5.1.1",
        "Ensure SNMP trap receivers is set"
    )

    out(
        INFO,
        "Objective : SNMP trap receivers must exist."
    )

    blank()

    snmp, source = find_native_snmp(root)

    if not snmp:

        out(
            FAIL,
            "Native SNMP configuration not found."
        )

        remediation(
            "Enable and configure SNMP."
        )

        return False

    receivers = get_trap_receivers(snmp)

    field("Detection Source", source)

    field(
        "Trap Receivers Found",
        str(len(receivers))
    )

    blank()

    if receivers:

        for idx, (tag, value) in enumerate(receivers, 1):

            field(
                f"Receiver #{idx}",
                f"{value} (tag: {tag})"
            )

        blank()

        out(
            PASS,
            "SNMP trap receivers are configured."
        )

        return True

    out(
        FAIL,
        "No SNMP trap receivers found."
    )

    remediation(
        "Configure at least one SNMP trap destination."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 5.1.2 SNMP Traps Enabled
# ─────────────────────────────────────────────────────────────────────────────

def check_5_1_2(root):

    section(
        "5.1.2",
        "Ensure SNMP traps is enabled"
    )

    out(
        INFO,
        "Objective : SNMP traps must be enabled."
    )

    blank()

    snmp, source = find_native_snmp(root)

    if not snmp:

        out(
            FAIL,
            "Native SNMP configuration not found."
        )

        return False

    enabled, tag, value = traps_enabled(snmp)

    field("Detection Source", source)

    field(
        "Trap Status",
        "ENABLED" if enabled else "DISABLED"
    )

    blank()

    if enabled:

        field("Detected Tag", tag)

        field("Detected Value", value)

        blank()

        out(
            PASS,
            "SNMP traps are enabled."
        )

        return True

    out(
        FAIL,
        "SNMP traps are NOT enabled."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 5.1.3 NET-SNMP
# ─────────────────────────────────────────────────────────────────────────────

def check_5_1_3(root):

    section(
        "5.1.3",
        "Ensure NET-SNMP package is securely configured"
    )

    out(
        INFO,
        "Objective : NET-SNMP must be securely configured."
    )

    blank()

    net_snmp_pkg = find_net_snmp_package(root)

    if not net_snmp_pkg:

        out(
            FAIL,
            "NET-SNMP package is NOT installed."
        )

        return False

    out(
        PASS,
        "NET-SNMP package is installed."
    )

    blank()

    overall = True

    community = (
        net_snmp_pkg.findtext(".//community", "") or ""
    ).strip()

    bind_ip = (
        net_snmp_pkg.findtext(".//bindip", "") or ""
    ).strip()

    poller = (
        net_snmp_pkg.findtext(".//poller", "") or ""
    ).strip()

    field(
        "Community String",
        community or "(not found)"
    )

    field(
        "Bind IP",
        bind_ip or "(not found)"
    )

    field(
        "Poller Restriction",
        poller or "(not found)"
    )

    blank()

    if not community:

        out(
            WARN,
            "Community string not found."
        )

        overall = False

    elif community.lower() in (
        "public",
        "private",
        "community"
    ):

        out(
            FAIL,
            f"Weak/default community detected: {community}"
        )

        overall = False

    else:

        out(
            PASS,
            "Community string acceptable."
        )

    if not bind_ip:

        out(
            WARN,
            "SNMP bind IP restriction not configured."
        )

        overall = False

    else:

        out(
            PASS,
            "Bind IP restriction configured."
        )

    if not poller:

        out(
            WARN,
            "SNMP poller restriction not configured."
        )

        overall = False

    else:

        out(
            PASS,
            "Poller restriction configured."
        )

    blank()

    if overall:

        out(
            PASS,
            "NET-SNMP package appears securely configured."
        )

    else:

        out(
            WARN,
            "NET-SNMP requires hardening review."
        )

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 5.2.1 TIMEZONE
# ─────────────────────────────────────────────────────────────────────────────

def check_5_2_1(root):

    section(
        "5.2.1",
        "Ensure time zone is properly configured"
    )

    out(
        INFO,
        "Objective : System timezone must be configured."
    )

    blank()

    timezone = (
        root.findtext("./system/timezone", "") or ""
    ).strip()

    field(
        "Detected Timezone",
        timezone if timezone else "(not found)"
    )

    blank()

    if not timezone:

        out(
            FAIL,
            "Timezone is not configured."
        )

        return False

    risky_values = [
        "utc",
        "gmt",
        "etc/utc",
        "etc/gmt",
        "default"
    ]

    if timezone.lower() in risky_values:

        out(
            WARN,
            f"Generic/default timezone detected: {timezone}"
        )

        return False

    out(
        PASS,
        "Timezone is explicitly configured."
    )

    return True

# ─────────────────────────────────────────────────────────────────────────────
# 5.3.1 DNSSEC
# ─────────────────────────────────────────────────────────────────────────────

def check_5_3_1(root):

    section(
        "5.3.1",
        "Ensure DNSSEC is Enabled on DNS Service"
    )

    out(
        INFO,
        "Objective : DNSSEC must be enabled."
    )

    blank()

    enabled, service, tag, value = get_dnssec_status(root)

    if service is None:

        out(
            FAIL,
            "No DNS service configuration found."
        )

        return False

    field("Detected Service", service)

    field(
        "DNSSEC Status",
        "ENABLED" if enabled else "DISABLED"
    )

    blank()

    if enabled:

        field("Detected Tag", tag)

        field("Detected Value", value)

        blank()

        out(
            PASS,
            "DNSSEC is enabled."
        )

        return True

    out(
        FAIL,
        "DNSSEC is NOT enabled."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 5.4.1 LDAP / RADIUS AUTH
# ─────────────────────────────────────────────────────────────────────────────

def check_5_4_1(root):

    section(
        "5.4.1",
        "Ensure RADIUS or LDAP are being used for VPN Authentication"
    )

    out(
        INFO,
        "Objective : VPN authentication should use LDAP or RADIUS."
    )

    blank()

    auth_servers = get_auth_servers(root)

    openvpn_servers = get_openvpn_servers(root)

    if not auth_servers:

        out(
            FAIL,
            "No authentication servers found."
        )

        return False

    ldap_radius_found = False

    for idx, auth in enumerate(auth_servers, 1):

        auth_type = (
            auth.findtext("type", "") or ""
        ).strip().lower()

        auth_name = (
            auth.findtext("name", "") or ""
        ).strip()

        field(
            f"Auth Server #{idx}",
            auth_name or "(unnamed)"
        )

        field(
            "Type",
            auth_type or "(not found)"
        )

        blank()

        if auth_type in ("ldap", "radius"):

            ldap_radius_found = True

            out(
                PASS,
                "Centralized authentication detected."
            )

        else:

            out(
                WARN,
                "Not LDAP/RADIUS."
            )

        blank()

    if not ldap_radius_found:

        out(
            FAIL,
            "No LDAP or RADIUS authentication detected."
        )

        return False

    vpn_uses_auth = False

    for idx, vpn in enumerate(openvpn_servers, 1):

        descr = (
            vpn.findtext("description", "") or ""
        ).strip()

        authmode = (
            vpn.findtext("authmode", "") or ""
        ).strip().lower()

        authserver = (
            vpn.findtext("authserver", "") or ""
        ).strip()

        field(
            f"VPN Server #{idx}",
            descr or "(unnamed)"
        )

        field(
            "Auth Mode",
            authmode or "(not found)"
        )

        field(
            "Auth Server Ref",
            authserver or "(not found)"
        )

        blank()

        if (
            "ldap" in authmode
            or "radius" in authmode
            or authserver
        ):

            vpn_uses_auth = True

            out(
                PASS,
                "VPN uses centralized authentication."
            )

        else:

            out(
                WARN,
                "VPN may still rely on local authentication."
            )

        blank()

    if vpn_uses_auth:

        out(
            PASS,
            "LDAP/RADIUS authentication appears configured."
        )

        return True

    out(
        FAIL,
        "VPN authentication configuration requires review."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 5.4.2 TRUSTED CERTIFICATE
# ─────────────────────────────────────────────────────────────────────────────

def check_5_4_2(root):

    section(
        "5.4.2",
        "Apply a Trusted Signed Certificate for VPN Portal"
    )

    out(
        INFO,
        "Objective : VPN should use CA-signed certificates."
    )

    blank()

    certs = get_certificates(root)

    if not certs:

        out(
            FAIL,
            "No certificates found."
        )

        return False

    trusted_found = False

    for idx, cert in enumerate(certs, 1):

        descr = (
            cert.findtext("descr", "") or ""
        ).strip()

        caref = (
            cert.findtext("caref", "") or ""
        ).strip()

        field(
            f"Certificate #{idx}",
            descr or "(unnamed)"
        )

        field(
            "CA Reference",
            caref or "(self-signed / none)"
        )

        blank()

        if caref:

            trusted_found = True

            out(
                PASS,
                "Certificate appears CA-signed."
            )

        else:

            out(
                WARN,
                "Possible self-signed certificate detected."
            )

        blank()

    if trusted_found:

        out(
            PASS,
            "Trusted certificates appear configured."
        )

        return True

    out(
        FAIL,
        "Only self-signed certificates detected."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 5.4.3 TLS ENCRYPTION
# ─────────────────────────────────────────────────────────────────────────────

def check_5_4_3(root):

    section(
        "5.4.3",
        "Ensure OpenVPN uses TLS encryption"
    )

    out(
        INFO,
        "Objective : OpenVPN must use TLS encryption."
    )

    blank()

    servers = get_openvpn_servers(root)

    if not servers:

        out(
            FAIL,
            "No OpenVPN servers found."
        )

        return False

    secure_found = False

    for idx, server in enumerate(servers, 1):

        descr = (
            server.findtext("description", "") or ""
        ).strip()

        mode = (
            server.findtext("mode", "") or ""
        ).strip()

        tls = (
            server.findtext("tls", "") or ""
        ).strip()

        tlsauth = (
            server.findtext("tlsauth_enable", "") or ""
        ).strip()

        tls_version = (
            server.findtext("tlsversionmin", "") or ""
        ).strip()

        cipher = normalize(
            server.findtext("crypto")
        )

        digest = normalize(
            server.findtext("digest")
        )

        field(
            f"OpenVPN Server #{idx}",
            descr or "(unnamed)"
        )

        field("Mode", mode or "(not found)")
        field("TLS", tls or "(not found)")
        field("TLS Auth", tlsauth or "(not found)")
        field("TLS Version", tls_version or "(not set)")
        field("Cipher", cipher or "(not set)")
        field("Digest", digest or "(not set)")

        blank()

        tls_enabled = (
            bool(tls)
            or tlsauth.lower() in (
                "yes",
                "on",
                "1",
                "true"
            )
            or mode.lower() == "server_tls"
        )

        if not tls_enabled:

            out(
                FAIL,
                "TLS protection not clearly detected."
            )

            blank()

            continue

        out(
            PASS,
            "TLS protection appears configured."
        )

        if tls_version in ("1.2", "1.3"):

            out(
                PASS,
                f"Strong TLS version detected ({tls_version})."
            )

        elif tls_version in ("1.0", "1.1"):

            out(
                FAIL,
                f"Weak TLS version detected ({tls_version})."
            )

        else:

            out(
                WARN,
                "TLS version not explicitly set."
            )

        if any(
            x in cipher
            for x in (
                "AES",
                "CHACHA20"
            )
        ):

            out(
                PASS,
                "Strong cipher detected."
            )

        else:

            out(
                WARN,
                "Cipher not recognized."
            )

        if digest in (
            "SHA256",
            "SHA384",
            "SHA512"
        ):

            out(
                PASS,
                "Strong digest detected."
            )

        elif digest in ("MD5", "SHA1"):

            out(
                FAIL,
                "Weak digest detected."
            )

        else:

            out(
                WARN,
                "Digest not recognized."
            )

        if (
            tls_version in ("1.2", "1.3")
            and digest.startswith("SHA")
        ):
            secure_found = True

        blank()


    if secure_found:

        out(
            PASS,
            "OpenVPN TLS configuration appears secure."
        )

        return True

    out(
        FAIL,
        "OpenVPN TLS configuration is NOT secure."
    )

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 5.5.1 STRONG CRYPTO
# ─────────────────────────────────────────────────────────────────────────────

def check_5_5_1(root):

    section(
        "5.5.1",
        "Ensure OpenVPN uses strong ciphers and hashing algorithms"
    )

    out(
        INFO,
        "Objective : Enforce strong cryptography."
    )

    blank()

    strong_ciphers = {
        "AES-256-GCM",
        "AES-128-GCM",
        "CHACHA20-POLY1305"
    }

    weak_ciphers = {
        "BF-CBC",
        "DES",
        "RC4",
        "3DES",
        "NULL"
    }

    strong_digests = {
        "SHA256",
        "SHA384",
        "SHA512"
    }

    weak_digests = {
        "MD5",
        "SHA1"
    }

    servers = get_openvpn_servers(root)

    if not servers:

        out(
            FAIL,
            "No OpenVPN servers found."
        )

        return False

    secure_found = False

    for idx, s in enumerate(servers, 1):

        descr = (
            s.findtext("description", "") or ""
        ).strip()

        cipher = normalize(
            s.findtext("crypto")
        )

        digest = normalize(
            s.findtext("digest")
        )

        tls_version = normalize(
            s.findtext("tlsversionmin")
        )

        ncp = normalize(
            s.findtext("ncp-ciphers")
            or s.findtext("data-ciphers")
        )

        custom = s.findtext(
            "custom_options",
            ""
        )

        custom_ciphers = extract_custom_options(
            custom,
            "data-ciphers"
        )

        tls_crypt = "tls-crypt" in custom
        tls_auth  = "tls-auth" in custom

        field(
            f"OpenVPN Server #{idx}",
            descr or "(unnamed)"
        )

        field(
            "TLS Version",
            tls_version or "(not set)"
        )

        field(
            "Cipher",
            cipher or "(not set)"
        )

        field(
            "Digest",
            digest or "(not set)"
        )

        field(
            "NCP/Data Ciphers",
            ncp or "(not set)"
        )

        blank()

        issues = []

        if not tls_version:

            out(
                WARN,
                "TLS version not set."
            )

        elif tls_version in ("1.0", "1.1"):

            issues.append(
                f"Weak TLS version ({tls_version})"
            )

            out(
                FAIL,
                f"Weak TLS version detected ({tls_version})."
            )

        else:

            out(
                PASS,
                f"Strong TLS version ({tls_version})."
            )

        if cipher in weak_ciphers:

            issues.append(
                f"Weak cipher ({cipher})"
            )

            out(
                FAIL,
                f"Weak cipher detected ({cipher})."
            )

        elif cipher in strong_ciphers:

            out(
                PASS,
                "Strong cipher detected."
            )

        else:

            out(
                WARN,
                "Cipher not recognized."
            )

        if digest in weak_digests:

            issues.append(
                f"Weak digest ({digest})"
            )

            out(
                FAIL,
                f"Weak digest detected ({digest})."
            )

        elif digest in strong_digests:

            out(
                PASS,
                "Strong digest detected."
            )

        else:

            out(
                WARN,
                "Digest not recognized."
            )

        if ncp:

            for c in [
                x.strip()
                for x in ncp.split(",")
            ]:

                if c in weak_ciphers:

                    issues.append(
                        f"Weak NCP cipher ({c})"
                    )

                    out(
                        FAIL,
                        f"Weak NCP cipher detected ({c})."
                    )

        for c in custom_ciphers:

            if c in weak_ciphers:

                issues.append(
                    f"Weak custom cipher ({c})"
                )

                out(
                    FAIL,
                    f"Weak custom cipher detected ({c})."
                )

        if not (tls_crypt or tls_auth):

            issues.append(
                "Missing tls-crypt/tls-auth"
            )

            out(
                WARN,
                "No tls-crypt or tls-auth detected."
            )

        if not issues:

            secure_found = True

            out(
                PASS,
                "Strong cryptographic configuration detected."
            )

        else:

            out(
                FAIL,
                "Weak or insecure crypto configuration detected."
            )

        blank()

    if secure_found:

        out(
            PASS,
            "OpenVPN cryptographic configuration is secure."
        )

    else:

        out(
            FAIL,
            "OpenVPN cryptographic configuration is NOT secure."
        )

        remediation(
            "Use AES-GCM or CHACHA20."
        )

        remediation(
            "Use SHA256 or stronger."
        )

        remediation(
            "Enforce TLS 1.2 or higher."
        )

        reference(
            "CIS pfSense Benchmark — Section 5.5.1"
        )

    return secure_found

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — LOGGING
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 6.1 SYSLOG CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

def get_syslog_config(root):
    return root.find("./syslog")

def check_6_1_syslog(root):

    section("6.1", "Ensure syslog is configured")

    out(INFO, "Objective : Ensure centralized logging is configured.")
    out(INFO, "            Logs should be forwarded to a remote syslog server.")
    out(DETAIL, "Rationale : Centralized logging improves monitoring,")
    out(DETAIL, "            incident response, and log retention.")

    blank()

    syslog_cfg = get_syslog_config(root)

    if syslog_cfg is None:

        out(FAIL, "No syslog configuration found.")

        remediation("Enable and configure remote syslog logging.")
        reference("CIS pfSense Benchmark — Section 6.1")

        return False

    remote_server = normalize_lower(
        syslog_cfg.findtext("remoteserver")
    )

    source_ip = normalize_lower(
        syslog_cfg.findtext("sourceip")
    )

    filterlogs = normalize_lower(
        syslog_cfg.findtext("filter")
    )

    dhcp = normalize_lower(
        syslog_cfg.findtext("dhcp")
    )

    portal = normalize_lower(
        syslog_cfg.findtext("portal")
    )

    vpn = normalize_lower(
        syslog_cfg.findtext("vpn")
    )

    field(
        "Remote Syslog Server",
        remote_server or "(not configured)"
    )

    field(
        "Source IP",
        source_ip or "(default)"
    )

    field(
        "Firewall Logs",
        "Enabled"
        if is_enabled(filterlogs)
        else "Not Explicitly Enabled"
    )

    field(
        "DHCP Logs",
        "Enabled"
        if is_enabled(dhcp)
        else "Not Explicitly Enabled"
    )

    field(
        "Portal Logs",
        "Enabled"
        if is_enabled(portal)
        else "Not Explicitly Enabled"
    )

    field(
        "VPN Logs",
        "Enabled"
        if is_enabled(vpn)
        else "Not Explicitly Enabled"
    )

    blank()

    issues = []

    if not remote_server:

        issues.append(
            "Remote syslog server not configured"
        )

        out(
            FAIL,
            "No remote syslog server configured."
        )

    else:

        out(
            PASS,
            "Remote syslog server configured."
        )

    if is_enabled(filterlogs):

        out(
            PASS,
            "Firewall logging enabled."
        )

    else:

        out(
            WARN,
            "Firewall logging not explicitly enabled."
        )

    if is_enabled(vpn):

        out(
            PASS,
            "VPN logging enabled."
        )

    else:

        out(
            WARN,
            "VPN logging not explicitly enabled."
        )

    if is_enabled(dhcp):

        out(
            PASS,
            "DHCP logging enabled."
        )

    else:

        out(
            WARN,
            "DHCP logging not explicitly enabled."
        )

    if is_enabled(portal):

        out(
            PASS,
            "Portal logging enabled."
        )

    else:

        out(
            WARN,
            "Portal logging not explicitly enabled."
        )

    if remote_server:

        if ":6514" in remote_server:

            out(
                PASS,
                "Secure syslog port detected (6514/TLS)."
            )

        elif ":514" in remote_server:

            out(
                WARN,
                "Standard syslog port detected (514/UDP)."
            )

        else:

            out(
                WARN,
                "Unknown syslog port configuration."
            )

    blank()



    if issues:

        out(
            FAIL,
            "Syslog configuration is incomplete."
        )

        remediation(
            "Configure remote syslog server for centralized logging."
        )

        remediation(
            "Use secure syslog transport where possible."
        )

        reference(
            "CIS pfSense Benchmark — Section 6.1"
        )

        return False

    out(
        PASS,
        "Syslog appears properly configured."
    )

    return True

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def run_audit(config_file: str) -> None:

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print()

    banner("CIS BENCHMARK — pfSense EXHAUSTIVE SECURITY AUDIT")
    banner("Sections 1 + 2 + 3 + 4 + 5 + 6")
    banner("GENERAL | USERS | PASSWORDS | FIREWALL | VPN | LOGGING")
    banner(f"File : {config_file}")
    banner(f"Time : {now}")

    try:

        tree = ET.parse(config_file)

        root = tree.getroot()

    except FileNotFoundError:

        print()

        out(
            FAIL,
            f"File not found: {config_file}"
        )

        sys.exit(1)

    except ET.ParseError as exc:

        print()

        out(
            FAIL,
            f"XML parse error: {exc}"
        )

        sys.exit(1)

    blank()

    out(
        DETAIL,
        "Device information from config.xml:"
    )

    version = safe_find_text(root, "version")

    family, edition = determine_pfsense_version(version)

    field(
        "Hostname",
        root.findtext("./system/hostname", "(not found)")
    )

    field(
        "Domain",
        root.findtext("./system/domain", "(not found)")
    )

    field(
        "Config version",
        version or "(not found)"
    )

    field(
        "Detected Family",
        family
    )

    field(
        "Edition",
        edition
    )

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 1
    # ─────────────────────────────────────────────────────────────────────────

    blank()

    banner("SECTION 1 — GENERAL SETTING POLICY")

    results = {}

    results["1.1 SSH Warning Banner"] = check_1_1(root)
    results["1.2 AutoConfigBackup"] = check_1_2(root)
    results["1.3 MOTD"] = check_1_3(root)
    results["1.4 Hostname"] = check_1_4(root)
    results["1.5 DNS Servers"] = check_1_5(root)
    results["1.6 IPv6"] = check_1_6(root)
    results["1.7 DNS Rebind"] = check_1_7(root)
    results["1.8 WebGUI HTTPS"] = check_1_8(root)
    results["1.9 High Availability"] = check_1_9(root)

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 2
    # ─────────────────────────────────────────────────────────────────────────

    blank()

    banner("SECTION 2 — USERS MANAGEMENT")

    results["2.1 Session Timeout"] = check_2_1_session_timeout(root)
    results["2.2 LDAP / RADIUS"] = check_2_2_external_auth(root)
    results["2.3 Console Password"] = check_2_3_console_password(root)
    results["2.4 Default Accounts"] = check_2_4_default_accounts(root)

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 3
    # ─────────────────────────────────────────────────────────────────────────

    blank()

    banner("SECTION 3 — PASSWORD POLICY")

    results["3.1 Local Accounts"] = check_3_1(root)
    results["3.2 Login Threshold"] = check_3_2(root)
    results["3.3 Lockout Duration"] = check_3_3(root)
    results["3.4 Default Passwords"] = check_3_4(root)

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 4
    # ─────────────────────────────────────────────────────────────────────────

    blank()

    banner("SECTION 4 — FIREWALL RULES POLICY")

    results["4.1.1 Destination Any"] = check_4_1_1_any_destination(root)
    results["4.1.2 Source Any"] = check_4_1_2_any_source(root)
    results["4.1.3 Service Any"] = check_4_1_3_any_service(root)
    results["4.1.4 Unused Policies"] = check_4_1_4_unused_policies(root)
    results["4.1.5 Rule Logging"] = check_4_1_5_rule_logging(root)
    results["4.1.6 ICMP Security"] = check_4_1_6_icmp_security(root)

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 5
    # ─────────────────────────────────────────────────────────────────────────

    blank()

    banner("SECTION 5 — INFRASTRUCTURE & VPN SECURITY")

    results["5.1.1 SNMP Trap Receivers"] = check_5_1_1(root)
    results["5.1.2 SNMP Traps Enabled"] = check_5_1_2(root)
    results["5.1.3 NET-SNMP Secure Configuration"] = check_5_1_3(root)
    results["5.2.1 Time Zone Properly Configured"] = check_5_2_1(root)
    results["5.3.1 DNSSEC Enabled"] = check_5_3_1(root)
    results["5.4.1 RADIUS/LDAP Authentication"] = check_5_4_1(root)
    results["5.4.2 Trusted Signed Certificate"] = check_5_4_2(root)
    results["5.4.3 OpenVPN TLS Encryption"] = check_5_4_3(root)
    results["5.5.1 Strong OpenVPN Crypto"] = check_5_5_1(root)

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 6
    # ─────────────────────────────────────────────────────────────────────────

    blank()

    banner("SECTION 6 — LOGGING")

    results["6.1 Syslog Configuration"] = check_6_1_syslog(root)

    # ══════════════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════════════════════════

    blank()

    banner("FINAL AUDIT SUMMARY")

    blank()

    passed = sum(
        1 for v in results.values() if v
    )

    total = len(results)

    for check, ok in results.items():

        status = PASS if ok else FAIL

        color = STATUS_COLORS[status]

        print(
            f"  {color}{status}{RESET}  {check}"
        )

    blank()

    percentage = int(
        (passed / total) * 100
    )

    print(
        f"  Compliance Score : {passed}/{total} checks passed ({percentage}%)"
    )

    blank()

    if passed == total:

        print(
            f"  {C.GREEN}✔ All {total} checks PASSED — configuration is COMPLIANT.{C.RESET}"
        )

    else:

        failed = total - passed

        print(
            f"  {C.RED}✘ {failed}/{total} check(s) FAILED — remediation required.{C.RESET}"
        )

        print(
            "     Review FAIL / WARN findings and apply corrective actions immediately."
        )

    blank()

    line("═")

    print(
        f"  Audit completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    line("═")

    blank()

# ══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    if len(sys.argv) == 2:

        config_path = sys.argv[1]

    else:

        config_path = input(
            "Enter path to pfSense config.xml: "
        ).strip()

    run_audit(config_path)
