#!/usr/bin/env python3
"""
CIS Benchmark — pfSense & OPNsense EXHAUSTIVE SECURITY AUDIT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Auto-detects platform from config.xml and adapts all XPath lookups
accordingly.

Sections covered:
  • Section 1 — General Settings
  • Section 2 — Users Management
  • Section 3 — Password Policy
  • Section 4 — Firewall Rules Policy
  • Section 5 — Infrastructure & VPN Security
  • Section 6 — Logging
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

DEFAULT_ACCOUNTS = {"admin", "root"}

DEFAULT_PASSWORDS = [
    "pfsense", "opnsense", "admin", "password", "123456",
    "root", "toor", "changeme", "default", "firewall",
    "pfsense1", "opnsense1", "netgate", "test", "1234",
]

# ══════════════════════════════════════════════════════════════════════════════
# PLATFORM DETECTION
# ══════════════════════════════════════════════════════════════════════════════

PLATFORM_PFSENSE  = "pfSense"
PLATFORM_OPNSENSE = "OPNsense"
PLATFORM_UNKNOWN  = "Unknown"


def detect_platform(root: ET.Element) -> str:
    """
    Detect whether the config.xml belongs to pfSense or OPNsense.

    OPNsense indicators:
      - <OPNsense> block present
      - version attribute on known OPNsense-only elements
      - <product> tag containing 'OPNsense'

    pfSense indicators:
      - <pfsense> root tag
      - <system><product> == 'pfSense'
      - presence of pfSense-specific tags
    """
    # Root tag check
    if root.tag.lower() == "pfsense":
        return PLATFORM_PFSENSE

    # Explicit OPNsense block
    if root.find("OPNsense") is not None:
        return PLATFORM_OPNSENSE

    # Product name in system
    product = (root.findtext("./system/product") or "").strip().lower()
    if "opnsense" in product:
        return PLATFORM_OPNSENSE
    if "pfsense" in product:
        return PLATFORM_PFSENSE

    # OPNsense-specific tags
    opnsense_tags = ["OPNsense", "netsnmp", "unboundplus", "TrafficShaper"]
    for tag in opnsense_tags:
        if root.find(f".//{tag}") is not None:
            return PLATFORM_OPNSENSE

    # pfSense-specific tags
    pfsense_tags = ["autoconfigbackup", "hasync", "sshguard_threshold"]
    for tag in pfsense_tags:
        if root.find(f".//{tag}") is not None:
            return PLATFORM_PFSENSE

    return PLATFORM_UNKNOWN


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
    print(f"{' ' * indent}↳ {label:<40} {value}")


def blank():
    print()


def remediation(text: str):
    print(f"            ⚠  Remediation : {text}")


def reference(text: str):
    print(f"            ⚑  Reference   : {text}")


def risk(level: str):
    colors = {
        "LOW":      C.GREEN,
        "MEDIUM":   C.YELLOW,
        "HIGH":     C.RED,
        "CRITICAL": C.MAGENTA,
    }
    color = colors.get(level.upper(), C.WHITE)
    print(f"            {color}Risk Level  : {level.upper()}{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# SHARED UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def normalize(value) -> str:
    return (value or "").strip().upper()


def normalize_lower(value) -> str:
    return (value or "").strip().lower()


def is_enabled(value) -> bool:
    return normalize_lower(value) in ("yes", "on", "1", "true", "enabled")


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
    return (secret[:visible] + "*" * (len(secret) - visible)
            if len(secret) > visible else "*" * len(secret))


def _decode_b64_keys(raw: str) -> list:
    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
        return [k.strip() for k in decoded.strip().splitlines() if k.strip()]
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


def verify_password(password: str, hash_value: str, hash_type: str) -> bool:
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


def test_default_passwords(hash_value: str, hash_type: str):
    for pwd in DEFAULT_PASSWORDS:
        if verify_password(pwd, hash_value, hash_type):
            return pwd
    return None


# ══════════════════════════════════════════════════════════════════════════════
# VERSION DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def determine_version(root: ET.Element, platform: str):
    """Return (version_string, family_name, edition)."""

    # OPNsense stores version differently
    if platform == PLATFORM_OPNSENSE:
        # Try <product_version>, <version>, or OPNsense block attributes
        version = (
            root.findtext("./system/product_version")
            or root.findtext("./system/version")
            or root.findtext("version")
            or ""
        ).strip()
        if not version:
            # Try reading from OPNsense child attributes
            opn = root.find("OPNsense")
            if opn is not None:
                for child in opn:
                    ver = child.get("version", "")
                    if ver:
                        version = ver
                        break
        return version or "Unknown", f"OPNsense {version or '?'}", "OPNsense"

    # pfSense
    version = (
        root.findtext("./system/version")
        or root.findtext("version")
        or ""
    ).strip()

    ce_map = {
        "2.4": "pfSense CE 2.4.x",
        "2.5": "pfSense CE 2.5.x",
        "2.6": "pfSense CE 2.6.x",
        "2.7": "pfSense CE 2.7.x",
    }
    plus_map = {
        "21": "pfSense Plus 21.x", "22": "pfSense Plus 22.x",
        "23": "pfSense Plus 23.x", "24": "pfSense Plus 24.x",
        "25": "pfSense Plus 25.x",
    }

    for prefix, name in ce_map.items():
        if version.startswith(prefix):
            return version, name, "Community Edition (CE)"
    for prefix, name in plus_map.items():
        if version.startswith(prefix):
            return version, name, "pfSense Plus"

    return version or "Unknown", "Unknown Version Family", "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# PLATFORM-AWARE XML HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_system_node(root: ET.Element, platform: str) -> ET.Element:
    return root.find("./system")


def find_text(root: ET.Element, platform: str, *xpaths) -> str:
    """Try multiple XPaths and return first non-empty match."""
    for xpath in xpaths:
        val = root.findtext(xpath, "")
        if val and val.strip():
            return val.strip()
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# USER EXTRACTION  (pfSense & OPNsense)
# ──────────────────────────────────────────────────────────────────────────────

def extract_users(root: ET.Element, platform: str) -> list:
    """
    pfSense  : <pfsense><system><user>…</user></system></pfsense>
    OPNsense : <opnsense><system><user>…</user></system></opnsense>
               also checks <system><user> at root level
    """
    users = []
    search_paths = [
        ".//system/user",
        ".//user",
    ]
    seen_names = set()
    for path in search_paths:
        for user in root.findall(path):
            username = (user.findtext("name") or "").strip()
            if not username or username in seen_names:
                continue
            seen_names.add(username)

            # Hash — OPNsense uses <password>, pfSense uses <bcrypt-hash>
            hash_value = (
                user.findtext("bcrypt-hash")
                or user.findtext("password")
                or user.findtext("passwordhash")
                or user.findtext("md5-hash")
                or ""
            ).strip()

            # If the "password" field doesn't look like a hash, ignore it
            if hash_value and not hash_value.startswith("$"):
                hash_value = ""

            users.append({
                "username": username,
                "hash":     hash_value,
                "disabled": user.find("disabled") is not None,
                "descr":    user.findtext("descr", ""),
                "scope":    user.findtext("scope", "local"),
                "priv":     [p.text for p in user.findall("priv") if p.text],
            })
    return users


# ──────────────────────────────────────────────────────────────────────────────
# FIREWALL RULE PARSER  (pfSense & OPNsense)
# ──────────────────────────────────────────────────────────────────────────────

def get_firewall_rules(root: ET.Element, platform: str) -> list:
    """
    pfSense  : <filter><rule>
    OPNsense : <filter><rule> AND <OPNsense><Firewall><…>
               OPNsense also stores rules under <OPNsense><Firewall>
               but the main rules are still in <filter><rule>.
    """
    rules = []

    # Common path — works for both
    for rule in root.findall("./filter/rule"):
        parsed = _parse_rule(rule)
        rules.append(parsed)

    # OPNsense extra rules inside <OPNsense><Firewall>
    if platform == PLATFORM_OPNSENSE:
        for rule in root.findall(".//OPNsense/Firewall//rule"):
            parsed = _parse_rule(rule)
            rules.append(parsed)

    return rules


def _parse_rule(rule: ET.Element) -> dict:
    parsed = {
        "type":        (rule.findtext("type") or "").strip(),
        "interface":   (rule.findtext("interface") or "").strip(),
        "descr":       (rule.findtext("descr") or rule.findtext("description") or "").strip(),
        "source":      "",
        "destination": "",
        "protocol":    (rule.findtext("protocol") or "").strip(),
        "log":         rule.find("log") is not None,
        "disabled":    rule.find("disabled") is not None,
    }

    src = rule.find("./source")
    if src is not None:
        parsed["source"] = (
            src.findtext("address")
            or src.findtext("network")
            or ("any" if src.find("any") is not None else "")
            or "unknown"
        )

    dst = rule.find("./destination")
    if dst is not None:
        parsed["destination"] = (
            dst.findtext("address")
            or dst.findtext("network")
            or ("any" if dst.find("any") is not None else "")
            or "unknown"
        )

    return parsed


# ──────────────────────────────────────────────────────────────────────────────
# VPN HELPERS  (pfSense & OPNsense)
# ──────────────────────────────────────────────────────────────────────────────

def get_auth_servers(root: ET.Element, platform: str) -> list:
    found = []
    paths = [
        "./system/authserver",
        "./system/authservers/authserver",
        ".//authserver",
    ]
    seen = set()
    for path in paths:
        for s in root.findall(path):
            sid = id(s)
            if sid not in seen:
                seen.add(sid)
                found.append(s)
    return found


def get_openvpn_servers(root: ET.Element, platform: str) -> list:
    found = []
    paths = [
        "./openvpn/openvpn-server",
        ".//openvpn-server",
    ]
    if platform == PLATFORM_OPNSENSE:
        paths += [
            ".//OPNsense/OpenVPN",
            ".//OpenVPN/Servers/Server",
        ]
    seen = set()
    for path in paths:
        for item in root.findall(path):
            sid = id(item)
            if sid not in seen:
                seen.add(sid)
                found.append(item)
    return found


def get_ipsec_config(root: ET.Element, platform: str):
    """Return IPsec phase1 entries."""
    entries = []
    if platform == PLATFORM_OPNSENSE:
        for p1 in root.findall(".//OPNsense/IPsec//phase1"):
            entries.append(p1)
        for p1 in root.findall(".//ipsec/phase1"):
            entries.append(p1)
    else:
        for p1 in root.findall(".//ipsec/phase1"):
            entries.append(p1)
    return entries


def get_certificates(root: ET.Element, platform: str) -> list:
    found = []
    paths = ["./cert", ".//cert"]
    if platform == PLATFORM_OPNSENSE:
        paths += [".//OPNsense//cert", ".//ca"]
    seen = set()
    for path in paths:
        for cert in root.findall(path):
            sid = id(cert)
            if sid not in seen:
                seen.add(sid)
                found.append(cert)
    return found


def extract_custom_options(options, keyword):
    results = []
    if not options:
        return results
    for line_ in options.splitlines():
        if keyword in line_:
            parts = line_.split()
            if len(parts) > 1:
                results.extend(re.split(r"[:,]", parts[1]))
    return [normalize(x) for x in results if x.strip()]


# ──────────────────────────────────────────────────────────────────────────────
# SNMP HELPERS  (pfSense & OPNsense)
# ──────────────────────────────────────────────────────────────────────────────

def find_snmp_config(root: ET.Element, platform: str):
    """
    pfSense  : <snmpd> or <snmp>
    OPNsense : <netsnmp><general> block
    Returns (snmp_element, source_label, is_opnsense_netsnmp)
    """
    if platform == PLATFORM_OPNSENSE:
        # Try <netsnmp>
        netsnmp = root.find(".//netsnmp")
        if netsnmp is not None:
            general = netsnmp.find("general")
            return (general or netsnmp), "<netsnmp><general>", True
        # Fallback to <snmpd>
        snmpd = root.find("snmpd")
        if snmpd is not None:
            return snmpd, "<snmpd>", False
        return None, None, False

    # pfSense
    snmpd = root.find("snmpd")
    if snmpd is not None:
        return snmpd, "native <snmpd>", False
    snmp = root.find("snmp")
    if snmp is not None:
        return snmp, "legacy <snmp>", False
    return None, None, False


def find_net_snmp_package(root: ET.Element, platform: str):
    for pkg in root.findall(".//installedpackages/package"):
        name = (pkg.findtext("name") or "").strip().lower()
        if name in ("net-snmp", "netsnmp", "net_snmp"):
            return pkg
    return None


def get_trap_receivers(snmp: ET.Element) -> list:
    tags = ["trapserver", "trap_receiver", "trapreceiver",
            "traphost", "receiver", "server"]
    receivers = []
    for tag in tags:
        for elem in snmp.findall(f".//{tag}"):
            value = (elem.text or "").strip()
            if value:
                receivers.append((tag, value))
    return receivers


def traps_enabled_check(snmp: ET.Element):
    tags = ["enabletrap", "trapsenable", "enable_traps",
            "trapenable", "enable"]
    for tag in tags:
        value = (snmp.findtext(f".//{tag}") or "").strip().lower()
        if value in ("yes", "true", "on", "1", "enabled"):
            return True, tag, value
    return False, None, None


# ──────────────────────────────────────────────────────────────────────────────
# DNSSEC HELPERS  (pfSense & OPNsense)
# ──────────────────────────────────────────────────────────────────────────────

def get_dnssec_status(root: ET.Element, platform: str):
    """Return (enabled, service_name, tag, value)."""

    if platform == PLATFORM_OPNSENSE:
        # OPNsense: <OPNsense><unboundplus> or <unbound>
        for path, svc in [
            (".//OPNsense/unboundplus", "OPNsense Unbound Plus"),
            (".//OPNsense/Unbound",     "OPNsense Unbound"),
            (".//unbound",              "DNS Resolver (Unbound)"),
        ]:
            node = root.find(path)
            if node is None:
                continue
            for tag in ("dnssec", "enable_dnssec", "dnssecenable"):
                val = (node.findtext(tag) or "").strip().lower()
                if val in ("yes", "true", "on", "1", "enabled", "1"):
                    return True, svc, tag, val
            return False, svc, None, None

    # pfSense
    unbound = root.find("unbound")
    if unbound is not None:
        for tag in ("enable_dnssec", "dnssec", "dnssecenable"):
            val = (unbound.findtext(tag) or "").strip().lower()
            if val in ("yes", "true", "on", "1", "enabled"):
                return True, "DNS Resolver (Unbound)", tag, val
        return False, "DNS Resolver (Unbound)", None, None

    dnsmasq = root.find("dnsmasq")
    if dnsmasq is not None:
        for tag in ("dnssec", "enable_dnssec", "dnssecenable"):
            val = (dnsmasq.findtext(tag) or "").strip().lower()
            if val in ("yes", "true", "on", "1", "enabled"):
                return True, "DNS Forwarder (dnsmasq)", tag, val
        return False, "DNS Forwarder (dnsmasq)", None, None

    return None, None, None, None


# ──────────────────────────────────────────────────────────────────────────────
# SYSLOG HELPERS  (pfSense & OPNsense)
# ──────────────────────────────────────────────────────────────────────────────

def get_syslog_config(root: ET.Element, platform: str):
    """
    pfSense  : <syslog>
    OPNsense : <OPNsense><Syslog> (plugin) AND/OR <syslog>
    Returns (element, source_label)
    """
    if platform == PLATFORM_OPNSENSE:
        opn_syslog = root.find(".//OPNsense/Syslog")
        if opn_syslog is not None:
            return opn_syslog, "OPNsense Syslog plugin"
    common = root.find("./syslog")
    if common is not None:
        return common, "Common <syslog>"
    return None, None


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 1 — GENERAL SETTING POLICY  ════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 1.1  SSH Warning Banner
# ─────────────────────────────────────────────────────────────────────────────

def check_1_1(root: ET.Element, platform: str) -> bool:
    section("1.1", "Ensure SSH warning banner is configured")
    out(INFO, "Objective : Administrative SSH access should display a legal warning banner.")
    out(DETAIL,"Rationale : Warning banners help support legal enforcement and monitoring.")
    blank()

    if platform == PLATFORM_OPNSENSE:
        # OPNsense SSH banner lives under system/ssh or system/sshbanner
        ssh_enabled = (
            root.find("./system/ssh") is not None
            or root.find("./system/enablesshd") is not None
        )
        ssh_banner = (
            root.findtext("./system/sshbanner")
            or root.findtext("./system/ssh/banner")
            or root.findtext("./system/motd")
            or ""
        )
        ssh_port = root.findtext("./system/ssh/port") or root.findtext("./system/sshport") or "22"
    else:
        ssh_enabled = root.find("./system/enablesshd") is not None
        ssh_banner  = (
            root.findtext("./system/sshguardmessage")
            or root.findtext("./system/sshbanner")
            or ""
        )
        ssh_port = root.findtext("./system/sshport") or "22"

    field("Platform",    platform)
    field("SSH Enabled", "YES" if ssh_enabled else "NO")
    field("SSH Port",    ssh_port)
    blank()

    if not ssh_enabled:
        out(INFO, "SSH service appears disabled — check skipped.")
        return True

    if ssh_banner and ssh_banner.strip():
        field("Banner Preview", ssh_banner[:100])
        blank()
        out(PASS, "SSH warning banner configured.")
        return True

    out(FAIL, "SSH enabled but no warning banner configured.")
    risk("MEDIUM")
    remediation("Configure a legal warning banner for SSH administrative access.")
    reference("CIS Benchmark — Section 1.1")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 1.2  AutoConfigBackup / Backup
# ─────────────────────────────────────────────────────────────────────────────

def check_1_2(root: ET.Element, platform: str) -> bool:
    section("1.2", "Ensure Automatic Configuration Backup is enabled")
    out(INFO, "Objective : Ensure configuration backups are enabled.")
    out(DETAIL,"Rationale : Backups help recover configurations after failure or compromise.")
    blank()

    field("Platform", platform)
    blank()

    if platform == PLATFORM_OPNSENSE:
        # OPNsense uses built-in backup; check for remote backup config
        # Paths: <system><backupcount>, or a package-based backup
        backup_count = root.findtext("./system/backupcount") or ""
        remote_backup = root.find(".//OPNsense/cron") is not None
        has_revision  = root.find("./revision") is not None

        field("Backup Count Setting", backup_count or "(not set)")
        field("Revision History",     "Present" if has_revision else "Absent")
        field("Cron (scheduled tasks)","Detected" if remote_backup else "Not Found")
        blank()

        if backup_count or has_revision:
            out(PASS, "OPNsense backup/revision mechanism detected.")
            return True

        out(WARN, "No explicit backup configuration detected — verify manually.")
        risk("MEDIUM")
        remediation("Enable System > Configuration > Backups and configure remote backup.")
        return False

    # pfSense
    acb = root.find("./installedpackages/autoconfigbackup")
    if acb is None:
        out(FAIL, "AutoConfigBackup package not installed.")
        risk("HIGH")
        remediation("Install and enable AutoConfigBackup under System > Package Manager.")
        return False

    enable_acb    = acb.findtext("./config/enable_acb") or acb.findtext(".//enable") or ""
    username      = acb.findtext("./config/username") or ""
    device_key    = acb.findtext("./config/device_key") or acb.findtext(".//device_key") or ""
    crypto_pw     = acb.findtext("./config/crypto_password") or ""

    field("AutoConfigBackup", enable_acb or "(not found)")
    field("Username",         username or "(not found)")
    field("Device Key",       "Present" if device_key else "Not Found")
    field("Backup Encryption","Configured" if crypto_pw else "Not Configured")
    blank()

    overall = True
    if is_enabled(enable_acb):
        out(PASS, "AutoConfigBackup is enabled.")
    else:
        out(FAIL, "AutoConfigBackup is disabled.")
        overall = False

    if crypto_pw:
        out(PASS, "Backup encryption configured.")
    else:
        out(WARN, "No backup encryption password configured.")
        overall = False

    blank()
    if overall:
        out(PASS, "AutoConfigBackup appears securely configured.")
    else:
        out(WARN, "AutoConfigBackup configuration requires review.")
        risk("MEDIUM")
    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 1.3  MOTD
# ─────────────────────────────────────────────────────────────────────────────

def check_1_3(root: ET.Element, platform: str) -> bool:
    section("1.3", "Ensure Message Of The Day (MOTD) is set")
    out(INFO, "Objective : Administrative systems should display a login notice.")
    blank()

    field("Platform", platform)
    blank()

    if platform == PLATFORM_OPNSENSE:
        motd = (
            root.findtext("./system/motd")
            or root.findtext("./system/ssh/motd")
            or ""
        )
    else:
        motd = root.findtext("./system/motd") or ""

    if motd and motd.strip():
        field("MOTD Preview", motd[:100])
        blank()
        out(PASS, "MOTD configured.")
        return True

    out(WARN, "MOTD not configured.")
    risk("LOW")
    remediation("Configure a legal or administrative MOTD banner.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 1.4  Hostname
# ─────────────────────────────────────────────────────────────────────────────

def check_1_4(root: ET.Element, platform: str) -> bool:
    section("1.4", "Ensure Hostname is set")
    out(INFO, "Objective : System hostname should be customized.")
    blank()

    field("Platform", platform)
    hostname = root.findtext("./system/hostname") or ""
    field("Hostname", hostname or "(not found)")
    blank()

    if not hostname:
        out(CRIT, "Hostname missing.")
        risk("HIGH")
        return False

    defaults = {"pfsense", "opnsense", "firewall", "router"}
    if hostname.lower() in defaults:
        out(WARN, f"Default hostname '{hostname}' still in use.")
        risk("LOW")
        remediation("Configure a unique, descriptive hostname.")
        return False

    out(PASS, "Custom hostname configured.")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 1.5  DNS Servers
# ─────────────────────────────────────────────────────────────────────────────

def check_1_5(root: ET.Element, platform: str) -> bool:
    section("1.5", "Ensure DNS server is configured")
    out(INFO, "Objective : DNS resolvers should be explicitly configured.")
    blank()

    field("Platform", platform)
    dns_servers = []

    for tag in root.findall("./system/dnsserver"):
        if tag.text and tag.text.strip():
            dns_servers.append(tag.text.strip())

    # Numbered fallback (pfSense legacy)
    for i in range(1, 5):
        dns = root.findtext(f"./system/dnsserver{i}") or ""
        if dns and dns not in dns_servers:
            dns_servers.append(dns)

    if dns_servers:
        field("DNS Servers Found", str(len(dns_servers)))
        blank()
        for idx, dns in enumerate(dns_servers, 1):
            field(f"DNS Server #{idx}", dns)
        blank()
        out(PASS, "DNS servers configured.")
        return True

    out(FAIL, "No DNS servers configured.")
    risk("HIGH")
    remediation("Configure trusted DNS resolvers under System > General Setup.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 1.6  IPv6
# ─────────────────────────────────────────────────────────────────────────────

def check_1_6(root: ET.Element, platform: str) -> bool:
    section("1.6", "Ensure IPv6 is disabled if not used")
    out(INFO, "Objective : Disable IPv6 when not operationally required.")
    blank()

    field("Platform", platform)
    blank()

    # OPNsense global IPv6 allow flag
    if platform == PLATFORM_OPNSENSE:
        global_ipv6 = root.findtext("./system/ipv6allow") or ""
        if global_ipv6:
            field("Global IPv6 Allow", global_ipv6)

    ipv6_found = False
    for interface in root.findall("./interfaces/*"):
        name = interface.tag
        ipv6 = interface.findtext("ipaddrv6") or ""
        if ipv6 and ipv6.strip():
            ipv6_found = True
            field(f"IPv6 Interface ({name})", ipv6)

    blank()

    if ipv6_found:
        out(WARN, "IPv6 configuration detected on one or more interfaces.")
        risk("MEDIUM")
        remediation("Disable IPv6 on unused interfaces if not required.")
        return False

    out(PASS, "IPv6 appears disabled on all interfaces.")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 1.7  DNS Rebind Check
# ─────────────────────────────────────────────────────────────────────────────

def check_1_7(root: ET.Element, platform: str) -> bool:
    section("1.7", "Ensure DNS Rebind Check is enabled")
    out(INFO, "Objective : DNS rebinding protection should remain enabled.")
    blank()

    field("Platform", platform)
    blank()

    if platform == PLATFORM_OPNSENSE:
        # OPNsense: check <system><webgui><nodnsrebindcheck>
        rebind_disabled = root.find("./system/webgui/nodnsrebindcheck")
        tag_used = "./system/webgui/nodnsrebindcheck"
    else:
        rebind_disabled = root.find("./system/dnsrebindcheck")
        tag_used = "./system/dnsrebindcheck"

    field("Tag checked", tag_used)
    field("Tag present", "YES (protection DISABLED)" if rebind_disabled is not None else "NO (protection ACTIVE)")
    blank()

    if rebind_disabled is not None:
        out(FAIL, "DNS Rebind protection is DISABLED — tag present.")
        risk("HIGH")
        remediation("Remove the DNS rebind check disable tag or uncheck the option in System > Advanced.")
        return False

    out(PASS, "DNS Rebind protection is ACTIVE.")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 1.8  WebGUI HTTPS
# ─────────────────────────────────────────────────────────────────────────────

def check_1_8(root: ET.Element, platform: str) -> bool:
    section("1.8", "Ensure Web Management is set to use HTTPS")
    out(INFO, "Objective : Web administration must use HTTPS.")
    blank()

    field("Platform", platform)

    if platform == PLATFORM_OPNSENSE:
        protocol = (
            root.findtext("./system/webgui/protocol")
            or root.findtext("./system/webui/protocol")
            or ""
        )
        port = (
            root.findtext("./system/webgui/port")
            or root.findtext("./system/webui/port")
            or ""
        )
    else:
        protocol = root.findtext("./system/webgui/protocol") or ""
        port     = root.findtext("./system/webgui/port") or ""

    field("Protocol", protocol or "(default)")
    field("Port",     port or "(default)")
    blank()

    if protocol.lower() == "https":
        out(PASS, "WebGUI uses HTTPS.")
        return True
    elif protocol.lower() == "http":
        out(CRIT, "WebGUI uses insecure HTTP!")
        risk("CRITICAL")
        remediation("Switch WebGUI to HTTPS in System > Administration.")
        return False

    out(WARN, "Protocol not explicitly defined — verify manually.")
    risk("MEDIUM")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 1.9  High Availability / CARP
# ─────────────────────────────────────────────────────────────────────────────

def check_1_9(root: ET.Element, platform: str) -> bool:
    section("1.9", "Ensure High Availability / CARP peer is configured")
    out(INFO, "Objective : HA/CARP synchronization should be configured.")
    blank()

    field("Platform", platform)
    blank()

    if platform == PLATFORM_OPNSENSE:
        # OPNsense: CARP/VHID config lives inside <virtualip> and
        # <OPNsense><Interfaces><vips>
        carp_found = False
        for vip in root.findall(".//virtualip/vip"):
            mode = (vip.findtext("mode") or "").strip().lower()
            if mode == "carp":
                carp_found = True
                field("CARP VIP", vip.findtext("subnet") or "(no subnet)")
                field("VHID",     vip.findtext("vhid") or "(not set)")
                field("Password", "Set" if vip.findtext("password") else "NOT SET")
                blank()

        if carp_found:
            out(PASS, "CARP/HA VIP detected.")
            return True

        out(WARN, "No CARP/HA VIP configuration found — may be single node.")
        risk("MEDIUM")
        remediation("Configure CARP VIPs under Interfaces > Virtual IPs if HA is required.")
        return False

    # pfSense
    hasync = root.find("./hasync")
    if hasync is None:
        out(FAIL, "No <hasync> block found.")
        risk("HIGH")
        remediation("Configure HA synchronization under System > High Availability Sync.")
        return False

    pfsync_enabled   = (hasync.findtext("pfsyncenabled") or "").strip()
    pfsync_iface     = (hasync.findtext("pfsyncinterface") or "").strip()
    pfsync_peerip    = (hasync.findtext("pfsyncpeerip") or "").strip()
    sync_target_ip   = (hasync.findtext("synchronizetoip") or "").strip()
    username         = (hasync.findtext("username") or "").strip()
    password         = (hasync.findtext("password") or "").strip()

    field("pfsync Enabled",    pfsync_enabled or "Not Found")
    field("pfsync Interface",  pfsync_iface or "Not Found")
    field("pfsync Peer IP",    pfsync_peerip or "Not Found")
    field("Sync Target IP",    sync_target_ip or "Not Found")
    field("Sync Username",     username or "Not Found")
    blank()

    overall = True
    if pfsync_enabled.lower() == "on" and pfsync_peerip:
        out(PASS, "pfsync enabled with peer.")
    else:
        out(FAIL, "pfsync synchronization incomplete.")
        overall = False

    if pfsync_iface:
        out(PASS, "Dedicated sync interface configured.")
    else:
        out(WARN, "No dedicated sync interface configured.")
        overall = False

    if sync_target_ip:
        out(PASS, "XMLRPC sync target configured.")
    else:
        out(WARN, "XMLRPC sync target missing.")
        overall = False

    if password:
        if len(password) < 12:
            out(WARN, "Sync password may be weak (< 12 chars).")
            overall = False
        else:
            out(PASS, "Sync password length acceptable.")
    else:
        out(WARN, "Sync password not found.")
        overall = False

    blank()
    if overall:
        out(PASS, "High Availability synchronization appears secure.")
    else:
        out(WARN, "HA configuration requires review.")
        risk("MEDIUM")
    return overall


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 2 — USERS MANAGEMENT  ══════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 2.1  Session Timeout
# ─────────────────────────────────────────────────────────────────────────────

def check_2_1(root: ET.Element, platform: str) -> bool:
    section("2.1", "Ensure Session Timeout is set to ≤ 10 Minutes")
    out(INFO, "Objective : GUI session must expire after ≤ 10 minutes of inactivity.")
    out(DETAIL,"Rationale : Long sessions increase attack window on unattended workstations.")
    blank()

    field("Platform", platform)
    blank()

    timeout_str = None
    source_xpath = None

    if platform == PLATFORM_OPNSENSE:
        candidates = [
            ("./system/webgui/session_timeout",    "./system/webgui/session_timeout"),
            ("./system/session_timeout",           "./system/session_timeout"),
            ("./system/webui/session_timeout",     "./system/webui/session_timeout"),
        ]
    else:
        candidates = [
            ("./system/webgui/session_timeout",    "./system/webgui/session_timeout"),
            ("./system/session_timeout",           "./system/session_timeout"),
        ]

    for xpath, label in candidates:
        val = root.findtext(xpath)
        if val:
            timeout_str = val
            source_xpath = label
            break

    field("Value found at", source_xpath or "not present")
    field("Raw XML value",  f"'{timeout_str}'" if timeout_str else "(tag absent)")
    blank()

    if timeout_str is None:
        out(FAIL, "Session timeout tag is ABSENT from config.")
        remediation("Set Session Timeout to ≤ 10 minutes in System > Administration.")
        return False

    try:
        timeout = int(timeout_str)
    except ValueError:
        out(FAIL, f"Session timeout value '{timeout_str}' is not a valid integer.")
        return False

    field("Parsed timeout",  f"{timeout} minute(s)")
    field("Maximum allowed", "10 minutes")
    blank()

    if timeout == 0:
        out(FAIL, "Timeout = 0 — sessions NEVER expire automatically.")
        remediation("Set a positive timeout ≤ 10 minutes.")
        return False

    if timeout < 0:
        out(FAIL, f"Timeout value {timeout} is invalid.")
        return False

    if timeout <= 10:
        out(PASS, f"Session timeout = {timeout} minute(s) — COMPLIANT.")
        return True

    out(FAIL, f"Session timeout = {timeout} minutes — exceeds 10-minute maximum.")
    remediation("Lower Session Timeout to ≤ 10 minutes.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 2.2  LDAP or RADIUS
# ─────────────────────────────────────────────────────────────────────────────

def check_2_2(root: ET.Element, platform: str) -> bool:
    section("2.2", "Ensure LDAP or RADIUS Server is Configured")
    out(INFO, "Objective : At least one LDAP or RADIUS authentication server must exist.")
    out(DETAIL,"Rationale : Centralized authentication improves governance and auditing.")
    blank()

    field("Platform", platform)
    blank()

    authservers = get_auth_servers(root, platform)
    out(DETAIL, f"Total <authserver> entries found: {len(authservers)}")
    blank()

    ldap_servers, radius_servers = [], []
    for auth in authservers:
        atype = (auth.findtext("type") or "").strip().lower()
        if "ldap" in atype:
            ldap_servers.append(auth)
        elif "radius" in atype:
            radius_servers.append(auth)

    for idx, server in enumerate(ldap_servers, 1):
        out(PASS, f"LDAP Server #{idx}: {server.findtext('name','Unknown')} @ {server.findtext('host','?')}")
    for idx, server in enumerate(radius_servers, 1):
        out(PASS, f"RADIUS Server #{idx}: {server.findtext('name','Unknown')} @ {server.findtext('host','?')}")

    if not ldap_servers and not radius_servers:
        out(FAIL, "NO LDAP or RADIUS authentication server is configured.")
        remediation("Configure centralized authentication under System > User Manager > Authentication Servers.")
        reference("CIS Benchmark — Section 2.2")
        return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# 2.3  Console Password Protection
# ─────────────────────────────────────────────────────────────────────────────

def check_2_3(root: ET.Element, platform: str) -> bool:
    section("2.3", "Ensure Console Menu is Password Protected")
    out(INFO, "Objective : Physical/serial console must require credentials.")
    out(DETAIL,"Rationale : Unprotected console allows bypass of all authentication.")
    blank()

    field("Platform", platform)
    blank()

    if platform == PLATFORM_OPNSENSE:
        # OPNsense: <system><console><password_protect> or <disableconsolemenu>
        pw_protect = root.findtext("./system/console/password_protect") or ""
        disable_tag = root.find("./system/disableconsolemenu")
        consolemenu = root.findtext("./system/console/consolemenu") or ""

        field("password_protect tag", pw_protect or "(absent)")
        field("disableconsolemenu",   "Present" if disable_tag is not None else "Absent")
        field("consolemenu",          consolemenu or "(absent)")
        blank()

        if pw_protect.lower() in ("enabled", "1", "true", "yes"):
            out(PASS, "Console password protection is explicitly enabled.")
            return True
        if disable_tag is not None:
            out(FAIL, "Console menu protection is DISABLED.")
            remediation("Enable console password protection in System > Administration.")
            return False
        out(PASS, "Console password protection appears ACTIVE (default OPNsense behavior).")
        return True

    # pfSense
    new_tag_val = root.findtext("./system/console/password_protected") or ""
    old_tag     = root.find("./system/disableconsolemenu")

    field("XPath (pfSense 2.5+)", "./system/console/password_protected")
    field("Value found",          f"'{new_tag_val}'" if new_tag_val else "(tag absent)")
    field("XPath (legacy ≤2.4)",  "./system/disableconsolemenu")
    field("Tag present",          "YES" if old_tag is not None else "NO")
    blank()

    if new_tag_val.lower() in ("enabled", "1", "true", "yes"):
        out(PASS, "Console password protection is enabled.")
        return True

    if old_tag is not None:
        out(FAIL, "Legacy <disableconsolemenu> detected — protection disabled.")
        remediation("Enable console password protection in System > Advanced > Admin Access.")
        reference("CIS pfSense Benchmark — Section 2.3")
        return False

    out(PASS, "Console password protection is ACTIVE (default).")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 2.4  Default Accounts
# ─────────────────────────────────────────────────────────────────────────────

def check_2_4(root: ET.Element, platform: str) -> bool:
    section("2.4", "Ensure All Default Accounts Are Disabled or Use Strong Passwords")
    out(INFO, "Objective : Built-in default accounts must be disabled or secured.")
    out(DETAIL,"Rationale : Default accounts are universally targeted by attackers.")
    blank()

    field("Platform", platform)
    blank()

    users = extract_users(root, platform)
    out(DETAIL, f"Total local accounts in config: {len(users)}")
    blank()

    overall       = True
    default_found = False

    for user in users:
        username = user["username"]
        if username.lower() not in DEFAULT_ACCOUNTS:
            continue
        default_found = True
        blank()
        line("┄")
        out(DETAIL, f"Deep evaluation of default account: '{username}'")
        line("┄")
        blank()

        field("Username", username)
        field("Status",   "DISABLED" if user["disabled"] else "ACTIVE")
        blank()

        if user["disabled"]:
            out(PASS, f"'{username}' is DISABLED.")
            continue

        out(WARN, f"'{username}' is ACTIVE — evaluating password security.")
        blank()

        hash_value = user["hash"]
        if not hash_value:
            out(CRIT, f"'{username}' has NO password hash.")
            overall = False
            continue

        hash_type = detect_hash_type(hash_value)
        field("Hash algorithm", hash_type)
        field("Hash preview",   hash_value[:25] + "…")
        blank()

        if hash_type == "bcrypt":
            variant = detect_bcrypt_variant(hash_value)
            cost    = _bcrypt_cost(hash_value)
            field("bcrypt variant",     f"${variant}$")
            field("bcrypt cost factor", str(cost))
            blank()
            if cost < MIN_BCRYPT_COST:
                out(FAIL, f"bcrypt cost factor {cost} is BELOW minimum {MIN_BCRYPT_COST}.")
                overall = False
            else:
                out(PASS, f"bcrypt cost factor = {cost} — COMPLIANT.")
        else:
            out(WARN, f"Hash type is {hash_type} — not bcrypt.")
            overall = False

        blank()
        out(DETAIL, f"Default password scan ({len(DEFAULT_PASSWORDS)} passwords tested):")
        matched = test_default_passwords(hash_value, hash_type)
        if matched:
            out(CRIT, f"DEFAULT PASSWORD DETECTED — matches '{matched}'")
            remediation(f"Change password for '{username}' immediately.")
            overall = False
        else:
            out(PASS, "Password does not match tested defaults.")
        blank()

    if not default_found:
        out(PASS, f"No accounts matching {DEFAULT_ACCOUNTS} were found.")

    if not overall:
        reference("CIS Benchmark — Section 2.4")
    return overall


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 3 — PASSWORD POLICY  ════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 3.1  Local Account Status
# ─────────────────────────────────────────────────────────────────────────────

def check_3_1(root: ET.Element, platform: str) -> bool:
    section("3.1", "Ensure Local Account Status is Reviewed")
    blank()

    field("Platform", platform)
    users    = extract_users(root, platform)
    active   = [u for u in users if not u["disabled"]]
    disabled = [u for u in users if u["disabled"]]

    field("Total Accounts",    str(len(users)))
    field("Active Accounts",   str(len(active)))
    field("Disabled Accounts", str(len(disabled)))
    blank()

    if len(users) == 0:
        out(FAIL, "No local accounts detected at all.")
        return False

    if len(active) == 0:
        out(FAIL, "No active local accounts — at least one admin account required.")
        return False

    if len(active) <= 3:
        out(PASS, "Local account configuration appears reasonable.")
        return True

    out(WARN, f"{len(active)} active local accounts detected.")
    remediation("Disable unnecessary or unused accounts.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 3.2  Login Protection Threshold
# ─────────────────────────────────────────────────────────────────────────────

def check_3_2(root: ET.Element, platform: str) -> bool:
    section("3.2", "Ensure Login Protection Threshold is set to 30 or less")
    blank()

    field("Platform", platform)

    if platform == PLATFORM_OPNSENSE:
        threshold = (
            root.findtext("./system/webgui/sshguard_threshold")
            or root.findtext("./system/sshguard_threshold")
            or root.findtext(".//OPNsense/Firewall//sshguard_threshold")
            or ""
        )
    else:
        threshold = (
            root.findtext("./system/sshguard_threshold")
            or root.findtext("./system/webgui/sshguard_threshold")
            or ""
        )

    if not threshold:
        out(FAIL, "Login protection threshold not configured.")
        remediation("Configure login protection threshold ≤ 30 in System > Advanced > Admin Access.")
        return False

    field("Threshold", threshold)
    blank()

    try:
        value = int(threshold)
    except ValueError:
        out(FAIL, "Invalid threshold value.")
        return False

    if value <= 30:
        out(PASS, f"Threshold = {value} (compliant)")
        if value <= 10:
            out(INFO, "Excellent security posture.")
        return True

    out(FAIL, f"Threshold = {value} exceeds 30.")
    remediation("Reduce threshold to ≤ 30.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 3.3  Lockout Duration
# ─────────────────────────────────────────────────────────────────────────────

def check_3_3(root: ET.Element, platform: str) -> bool:
    section("3.3", "Ensure Lockout Duration is set to 300s or more")
    blank()

    field("Platform", platform)

    if platform == PLATFORM_OPNSENSE:
        blocktime = (
            root.findtext("./system/webgui/sshguard_blocktime")
            or root.findtext("./system/sshguard_blocktime")
            or ""
        )
    else:
        blocktime = (
            root.findtext("./system/sshguard_blocktime")
            or root.findtext("./system/webgui/sshguard_blocktime")
            or ""
        )

    if not blocktime:
        out(FAIL, "Lockout duration not configured.")
        remediation("Set lockout duration ≥ 300 seconds.")
        return False

    field("Lockout Duration", f"{blocktime} seconds")
    blank()

    try:
        value = int(blocktime)
    except ValueError:
        out(FAIL, "Invalid lockout duration.")
        return False

    if value >= 300:
        out(PASS, f"Lockout duration = {value}s (compliant)")
        return True

    out(FAIL, f"Lockout duration = {value}s is too low.")
    remediation("Set lockout duration ≥ 300 seconds.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 3.4  Default Passwords (all accounts)
# ─────────────────────────────────────────────────────────────────────────────

def check_3_4(root: ET.Element, platform: str) -> bool:
    section("3.4", "Ensure Default Passwords Are Changed")
    out(INFO, f"Objective : Detect default/weak passwords across ALL local accounts.")
    out(INFO,  f"            Tests each hash against {len(DEFAULT_PASSWORDS)} known passwords.")
    blank()

    field("Platform", platform)
    blank()

    users = extract_users(root, platform)
    if not users:
        out(FAIL, "No users found.")
        return False

    secure = True
    for idx, user in enumerate(users, 1):
        username   = user["username"]
        hash_value = user["hash"]

        line("┄")
        out(DETAIL, f"User #{idx} Password Review")
        line("┄")
        blank()

        field("Username", username)
        field("Status",   "DISABLED" if user["disabled"] else "ACTIVE")
        blank()

        if not hash_value:
            out(CRIT, "No password hash found — account may have no password.")
            secure = False
            blank()
            continue

        hash_type = detect_hash_type(hash_value)
        field("Hash Type",     hash_type)
        if hash_type == "bcrypt":
            field("bcrypt Variant", detect_bcrypt_variant(hash_value))
        field("Hash (preview)", hash_value[:60] + "…")
        blank()

        if hash_type == "Unknown":
            out(WARN, "Unknown hash type — cannot verify password.")
            secure = False
            blank()
            continue

        matched = test_default_passwords(hash_value, hash_type)
        if matched:
            out(FAIL, f"Default password detected: '{matched}'")
            remediation(f"Change password immediately for user '{username}'.")
            secure = False
        else:
            out(PASS, "Password does not match any known defaults.")

        blank()

    return secure


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 4 — FIREWALL RULES POLICY  ══════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════

def _firewall_rule_header(idx, rule):
    field("Rule",        f"#{idx}")
    field("Description", rule["descr"] or "(none)")
    field("Interface",   rule["interface"] or "(none)")
    field("Type",        rule["type"] or "(none)")


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.1  No Allow Rule with Any Destination
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_1(root: ET.Element, platform: str) -> bool:
    section("4.1.1", "Ensure no Allow Rule with Any in Destination Field")
    out(INFO, "Objective : No PASS rule should allow traffic to destination 'any'.")
    out(DETAIL,"Rationale : 'Allow → Any Destination' permits unrestricted outbound access.")
    blank()

    field("Platform", platform)
    rules = get_firewall_rules(root, platform)
    field("Total firewall rules", str(len(rules)))
    blank()

    findings = []
    overall  = True

    for idx, rule in enumerate(rules, 1):
        if rule["disabled"] or rule["type"].lower() != "pass":
            continue
        destination = str(rule["destination"]).lower()
        if destination in ("any", "", "unknown"):
            _firewall_rule_header(idx, rule)
            field("Destination", rule["destination"])
            blank()
            out(FAIL, "Allow rule uses destination = ANY")
            findings.append(rule)
            overall = False
            blank()

    if findings:
        out(FAIL, f"{len(findings)} risky allow rule(s) found using destination ANY.")
        remediation("Replace destination 'any' with specific hosts, networks, or aliases.")
        reference("CIS Benchmark — Section 4.1.1")
    else:
        out(PASS, "No allow rules with destination ANY were found.")

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.2  No Allow Rule with Any Source
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_2(root: ET.Element, platform: str) -> bool:
    section("4.1.2", "Ensure no Allow Rule with Any in Source Field")
    out(INFO, "Objective : No PASS rule should allow traffic from source 'any'.")
    out(DETAIL,"Rationale : 'Allow from Any Source' permits unknown/untrusted origins.")
    blank()

    field("Platform", platform)
    rules = get_firewall_rules(root, platform)
    field("Total firewall rules", str(len(rules)))
    blank()

    findings = []
    overall  = True

    for idx, rule in enumerate(rules, 1):
        if rule["disabled"] or rule["type"].lower() != "pass":
            continue
        source = str(rule["source"]).lower()
        if source in ("any", "", "unknown"):
            _firewall_rule_header(idx, rule)
            field("Source", rule["source"])
            blank()
            out(FAIL, "Allow rule uses source = ANY")
            findings.append(rule)
            overall = False
            blank()

    if findings:
        out(FAIL, f"{len(findings)} risky allow rule(s) found using source ANY.")
        remediation("Replace source 'any' with specific trusted networks or hosts.")
        reference("CIS Benchmark — Section 4.1.2")
    else:
        out(PASS, "No allow rules with source ANY were found.")

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.3  No Allow Rule with Any Service
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_3(root: ET.Element, platform: str) -> bool:
    section("4.1.3", "Ensure no Allow Rule with Any in Services Field")
    out(INFO, "Objective : PASS rules must not allow service/protocol = ANY.")
    out(DETAIL,"Rationale : Allowing ANY service exposes all ports and protocols.")
    blank()

    field("Platform", platform)
    rules = get_firewall_rules(root, platform)
    field("Total firewall rules", str(len(rules)))
    blank()

    findings = []
    overall  = True

    for idx, rule in enumerate(rules, 1):
        if rule["disabled"] or rule["type"].lower() != "pass":
            continue
        protocol = str(rule["protocol"]).lower()
        if protocol in ("", "any"):
            _firewall_rule_header(idx, rule)
            field("Protocol/Service", rule["protocol"] or "any")
            blank()
            out(FAIL, "Allow rule uses service/protocol = ANY")
            findings.append(rule)
            overall = False
            blank()

    if findings:
        out(FAIL, f"{len(findings)} risky allow rule(s) found using ANY service.")
        remediation("Replace protocol 'any' with explicit services only.")
        reference("CIS Benchmark — Section 4.1.3")
    else:
        out(PASS, "No allow rules with ANY service were found.")

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.4  Unused Policies
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_4(root: ET.Element, platform: str) -> bool:
    section("4.1.4", "Ensure there are no Unused Policies")
    out(INFO, "Objective : Firewall policies must be actively used and justified.")
    out(DETAIL,"Rationale : Stale rules create hidden risk and configuration drift.")
    blank()

    field("Platform", platform)
    rules = get_firewall_rules(root, platform)
    field("Total firewall rules", str(len(rules)))
    blank()

    findings = []
    overall  = True
    suspicious_keywords = [
        "temp", "temporary", "test", "old", "legacy",
        "migration", "debug", "troubleshoot", "unused", "backup",
    ]

    for idx, rule in enumerate(rules, 1):
        descr = (rule["descr"] or "").lower()
        suspicious = False

        if rule["disabled"]:
            _firewall_rule_header(idx, rule)
            out(WARN, "Rule is disabled — possible obsolete policy.")
            suspicious = True

        if not rule["descr"].strip():
            if not suspicious:
                _firewall_rule_header(idx, rule)
            out(WARN, "Rule has no description.")
            suspicious = True

        for kw in suspicious_keywords:
            if kw in descr:
                if not suspicious:
                    _firewall_rule_header(idx, rule)
                out(WARN, f"Description contains suspicious keyword: '{kw}'")
                suspicious = True
                break

        if suspicious:
            findings.append(rule)
            overall = False
            blank()

    if findings:
        out(WARN, f"{len(findings)} rule(s) require manual review.")
        remediation("Review logs and remove obsolete or temporary rules.")
        reference("CIS Benchmark — Section 4.1.4")
    else:
        out(PASS, "No obvious unused policies detected.")

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.5  Logging Enabled for Firewall Rules
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_5(root: ET.Element, platform: str) -> bool:
    section("4.1.5", "Ensure Logging is Enabled for All Firewall Rules")
    out(INFO, "Objective : Security-relevant firewall rules must have logging enabled.")
    out(DETAIL,"Rationale : Without logging, attacks and policy violations remain invisible.")
    blank()

    field("Platform", platform)
    rules = get_firewall_rules(root, platform)
    field("Total firewall rules", str(len(rules)))
    blank()

    findings = []
    overall  = True

    for idx, rule in enumerate(rules, 1):
        if rule["disabled"]:
            continue
        if not rule["log"]:
            _firewall_rule_header(idx, rule)
            field("Logging", "DISABLED")
            blank()
            out(WARN, "Logging is disabled for this rule.")
            findings.append(rule)
            overall = False
            blank()

    if findings:
        out(WARN, f"{len(findings)} rule(s) found without logging enabled.")
        remediation("Enable logging for critical rules (WAN, PASS, admin, VPN).")
        reference("CIS Benchmark — Section 4.1.5")
    else:
        out(PASS, "Logging is enabled for all active rules.")

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.6  ICMP Security
# ─────────────────────────────────────────────────────────────────────────────

def check_4_1_6(root: ET.Element, platform: str) -> bool:
    section("4.1.6", "Ensure ICMP Rules are Securely Configured")
    out(INFO, "Objective : ICMP must be restricted to legitimate operational needs.")
    out(DETAIL,"Rationale : Unrestricted ICMP increases reconnaissance exposure.")
    blank()

    field("Platform", platform)
    rules = get_firewall_rules(root, platform)
    field("Total firewall rules", str(len(rules)))
    blank()

    findings = []
    overall  = True

    for idx, rule in enumerate(rules, 1):
        if rule["disabled"]:
            continue
        protocol = str(rule["protocol"]).lower()
        if protocol != "icmp":
            continue

        if rule["type"].lower() == "pass":
            risky = False
            _firewall_rule_header(idx, rule)
            field("Source",      rule["source"])
            field("Destination", rule["destination"])
            blank()

            if str(rule["source"]).lower() in ("any", "", "unknown"):
                out(WARN, "ICMP allowed from ANY source.")
                risky = True
            if str(rule["destination"]).lower() in ("any", "", "unknown"):
                out(WARN, "ICMP allowed to ANY destination.")
                risky = True
            if risky:
                out(DETAIL, "Broad ICMP exposure detected.")
                findings.append(rule)
                overall = False
            else:
                out(PASS, "ICMP rule appears reasonably restricted.")
            blank()

    if findings:
        out(WARN, f"{len(findings)} risky ICMP rule(s) require review.")
        remediation("Restrict ICMP to trusted management/monitoring networks.")
        reference("CIS Benchmark — Section 4.1.6")
    else:
        out(PASS, "No risky ICMP configurations detected.")

    return overall


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 5 — INFRASTRUCTURE & VPN SECURITY  ═════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 5.1.1  SNMP Trap Receivers
# ─────────────────────────────────────────────────────────────────────────────

def check_5_1_1(root: ET.Element, platform: str) -> bool:
    section("5.1.1", "Ensure SNMP trap receivers are set")
    out(INFO, "Objective : SNMP trap receivers must exist.")
    blank()

    field("Platform", platform)
    blank()

    snmp, source, is_opn = find_snmp_config(root, platform)

    if snmp is None:
        out(FAIL, "SNMP configuration not found.")
        remediation("Enable and configure SNMP.")
        return False

    field("Detection Source", source)
    blank()

    if is_opn:
        # OPNsense netsnmp: trap config
        trap_server  = snmp.findtext("trapserver")  or snmp.findtext("trap_server")  or ""
        trap_enabled = snmp.findtext("trap")         or snmp.findtext("trapenabled") or ""

        field("Trap Server",  trap_server or "(not set)")
        field("Trap Enabled", trap_enabled or "(not set)")
        blank()

        if trap_server:
            out(PASS, f"SNMP trap receiver configured: {trap_server}")
            return True
        out(FAIL, "No SNMP trap receiver configured.")
        remediation("Configure SNMP trap destination in Services > Net-SNMP.")
        return False

    # pfSense
    receivers = get_trap_receivers(snmp)
    field("Trap Receivers Found", str(len(receivers)))
    blank()

    if receivers:
        for idx, (tag, value) in enumerate(receivers, 1):
            field(f"Receiver #{idx}", f"{value} (tag: {tag})")
        blank()
        out(PASS, "SNMP trap receivers are configured.")
        return True

    out(FAIL, "No SNMP trap receivers found.")
    remediation("Configure at least one SNMP trap destination.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 5.1.2  SNMP Traps Enabled
# ─────────────────────────────────────────────────────────────────────────────

def check_5_1_2(root: ET.Element, platform: str) -> bool:
    section("5.1.2", "Ensure SNMP traps are enabled")
    out(INFO, "Objective : SNMP traps must be enabled.")
    blank()

    field("Platform", platform)
    blank()

    snmp, source, is_opn = find_snmp_config(root, platform)

    if snmp is None:
        out(FAIL, "SNMP configuration not found.")
        return False

    field("Detection Source", source)
    blank()

    if is_opn:
        # OPNsense: <enabled> under <general>
        enabled_val = snmp.findtext("enabled") or ""
        trap_val    = snmp.findtext("trap") or snmp.findtext("trapenabled") or ""

        field("SNMP Enabled", enabled_val or "(not set)")
        field("Trap Setting", trap_val    or "(not set)")
        blank()

        if is_enabled(enabled_val):
            out(PASS, "SNMP is enabled (OPNsense netsnmp).")
            if is_enabled(trap_val):
                out(PASS, "SNMP traps are enabled.")
                return True
            out(WARN, "SNMP enabled but trap setting not explicitly on.")
            return False
        out(FAIL, "SNMP is NOT enabled.")
        return False

    # pfSense
    enabled, tag, value = traps_enabled_check(snmp)
    field("Trap Status", "ENABLED" if enabled else "DISABLED")
    blank()

    if enabled:
        field("Detected Tag",   tag)
        field("Detected Value", value)
        blank()
        out(PASS, "SNMP traps are enabled.")
        return True

    out(FAIL, "SNMP traps are NOT enabled.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 5.1.3  SNMP Community String / NET-SNMP
# ─────────────────────────────────────────────────────────────────────────────

def check_5_1_3(root: ET.Element, platform: str) -> bool:
    section("5.1.3", "Ensure SNMP is securely configured (community string etc.)")
    out(INFO, "Objective : SNMP must use strong community strings and restricted binding.")
    blank()

    field("Platform", platform)
    blank()

    overall = True

    if platform == PLATFORM_OPNSENSE:
        snmp, source, _ = find_snmp_config(root, platform)

        if snmp is None:
            out(FAIL, "SNMP configuration not found.")
            return False

        community = (snmp.findtext("community") or "").strip()
        bind_ip   = (snmp.findtext("bindip") or snmp.findtext("listenip") or "").strip()
        sysloc    = (snmp.findtext("syslocation") or "").strip()
        syscont   = (snmp.findtext("syscontact") or "").strip()

        field("Detection Source",  source)
        field("Community String",  community or "(not found)")
        field("Bind/Listen IP",    bind_ip or "(not found)")
        field("System Location",   sysloc or "(not set)")
        field("System Contact",    syscont or "(not set)")
        blank()

        if not community:
            out(WARN, "Community string not found.")
            overall = False
        elif community.lower() in ("public", "private", "community", "default"):
            out(FAIL, f"Weak/default community string detected: '{community}'")
            overall = False
        else:
            out(PASS, "Community string is not a well-known default.")

        if not bind_ip:
            out(WARN, "SNMP bind IP restriction not configured.")
            overall = False
        else:
            out(PASS, f"Bind IP restriction: {bind_ip}")

        blank()
        if overall:
            out(PASS, "SNMP appears securely configured.")
        else:
            out(WARN, "SNMP requires hardening review.")
        return overall

    # pfSense — check net-snmp package
    net_snmp_pkg = find_net_snmp_package(root, platform)
    if not net_snmp_pkg:
        out(FAIL, "NET-SNMP package is NOT installed.")
        return False

    out(PASS, "NET-SNMP package is installed.")
    blank()

    community  = (net_snmp_pkg.findtext(".//community") or "").strip()
    bind_ip    = (net_snmp_pkg.findtext(".//bindip") or "").strip()
    poller     = (net_snmp_pkg.findtext(".//poller") or "").strip()

    field("Community String",    community or "(not found)")
    field("Bind IP",             bind_ip or "(not found)")
    field("Poller Restriction",  poller or "(not found)")
    blank()

    if not community:
        out(WARN, "Community string not found.")
        overall = False
    elif community.lower() in ("public", "private", "community"):
        out(FAIL, f"Weak/default community detected: {community}")
        overall = False
    else:
        out(PASS, "Community string acceptable.")

    if not bind_ip:
        out(WARN, "SNMP bind IP restriction not configured.")
        overall = False
    else:
        out(PASS, "Bind IP restriction configured.")

    if not poller:
        out(WARN, "SNMP poller restriction not configured.")
        overall = False
    else:
        out(PASS, "Poller restriction configured.")

    blank()
    if overall:
        out(PASS, "NET-SNMP package appears securely configured.")
    else:
        out(WARN, "NET-SNMP requires hardening review.")

    return overall


# ─────────────────────────────────────────────────────────────────────────────
# 5.2.1  Timezone
# ─────────────────────────────────────────────────────────────────────────────

def check_5_2_1(root: ET.Element, platform: str) -> bool:
    section("5.2.1", "Ensure time zone is properly configured")
    out(INFO, "Objective : System timezone must be explicitly configured.")
    blank()

    field("Platform", platform)
    blank()

    timezone = (
        root.findtext("./system/timezone")
        or root.findtext("./system/timeservers")
        or ""
    ).strip()

    field("Detected Timezone", timezone or "(not found)")
    blank()

    if not timezone:
        out(FAIL, "Timezone is not configured.")
        remediation("Set timezone under System > General Setup.")
        return False

    risky = {"utc", "gmt", "etc/utc", "etc/gmt", "default"}
    if timezone.lower() in risky:
        out(WARN, f"Generic/default timezone detected: {timezone}")
        remediation("Configure an explicit regional timezone.")
        return False

    out(PASS, "Timezone is explicitly configured.")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 5.3.1  DNSSEC
# ─────────────────────────────────────────────────────────────────────────────

def check_5_3_1(root: ET.Element, platform: str) -> bool:
    section("5.3.1", "Ensure DNSSEC is Enabled on DNS Service")
    out(INFO, "Objective : DNSSEC must be enabled.")
    blank()

    field("Platform", platform)
    blank()

    enabled, service, tag, value = get_dnssec_status(root, platform)

    if service is None:
        out(FAIL, "No DNS service configuration found.")
        return False

    field("Detected Service", service)
    field("DNSSEC Status",    "ENABLED" if enabled else "DISABLED")
    blank()

    if enabled:
        field("Detected Tag",   tag)
        field("Detected Value", value)
        blank()
        out(PASS, "DNSSEC is enabled.")
        return True

    out(FAIL, "DNSSEC is NOT enabled.")
    remediation("Enable DNSSEC in Services > DNS Resolver (Unbound).")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 5.4.1  LDAP / RADIUS for VPN Auth
# ─────────────────────────────────────────────────────────────────────────────

def check_5_4_1(root: ET.Element, platform: str) -> bool:
    section("5.4.1", "Ensure RADIUS or LDAP are used for VPN Authentication")
    out(INFO, "Objective : VPN authentication should use LDAP or RADIUS.")
    blank()

    field("Platform", platform)
    blank()

    auth_servers    = get_auth_servers(root, platform)
    openvpn_servers = get_openvpn_servers(root, platform)

    if not auth_servers:
        out(FAIL, "No authentication servers found.")
        return False

    ldap_radius_found = False
    for idx, auth in enumerate(auth_servers, 1):
        atype = (auth.findtext("type") or "").strip().lower()
        aname = (auth.findtext("name") or "").strip()
        field(f"Auth Server #{idx}", aname or "(unnamed)")
        field("Type",                atype or "(not found)")
        blank()
        if atype in ("ldap", "radius"):
            ldap_radius_found = True
            out(PASS, "Centralized authentication detected.")
        else:
            out(WARN, "Not LDAP/RADIUS.")
        blank()

    if not ldap_radius_found:
        out(FAIL, "No LDAP or RADIUS authentication detected.")
        return False

    vpn_uses_auth = False
    for idx, vpn in enumerate(openvpn_servers, 1):
        descr      = (vpn.findtext("description") or vpn.findtext("descr") or "").strip()
        authmode   = (vpn.findtext("authmode")   or "").strip().lower()
        authserver = (vpn.findtext("authserver") or "").strip()

        field(f"VPN Server #{idx}", descr or "(unnamed)")
        field("Auth Mode",          authmode or "(not found)")
        field("Auth Server Ref",    authserver or "(not found)")
        blank()

        if "ldap" in authmode or "radius" in authmode or authserver:
            vpn_uses_auth = True
            out(PASS, "VPN uses centralized authentication.")
        else:
            out(WARN, "VPN may still rely on local authentication.")
        blank()

    if vpn_uses_auth:
        out(PASS, "LDAP/RADIUS VPN authentication appears configured.")
        return True

    out(FAIL, "VPN authentication configuration requires review.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 5.4.2  Trusted Certificate
# ─────────────────────────────────────────────────────────────────────────────

def check_5_4_2(root: ET.Element, platform: str) -> bool:
    section("5.4.2", "Apply a Trusted Signed Certificate for VPN Portal")
    out(INFO, "Objective : VPN should use CA-signed certificates.")
    blank()

    field("Platform", platform)
    blank()

    certs = get_certificates(root, platform)
    if not certs:
        out(FAIL, "No certificates found.")
        return False

    trusted_found = False
    for idx, cert in enumerate(certs, 1):
        descr = (cert.findtext("descr") or cert.findtext("description") or "").strip()
        caref = (cert.findtext("caref") or "").strip()
        field(f"Certificate #{idx}", descr or "(unnamed)")
        field("CA Reference",        caref or "(self-signed / none)")
        blank()
        if caref:
            trusted_found = True
            out(PASS, "Certificate appears CA-signed.")
        else:
            out(WARN, "Possible self-signed certificate detected.")
        blank()

    if trusted_found:
        out(PASS, "Trusted certificates appear configured.")
        return True

    out(FAIL, "Only self-signed certificates detected.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 5.4.3  OpenVPN TLS Encryption
# ─────────────────────────────────────────────────────────────────────────────

def check_5_4_3(root: ET.Element, platform: str) -> bool:
    section("5.4.3", "Ensure OpenVPN uses TLS encryption")
    out(INFO, "Objective : OpenVPN must use TLS encryption.")
    blank()

    field("Platform", platform)
    blank()

    servers = get_openvpn_servers(root, platform)

    # OPNsense: also look for IPsec as a fallback VPN
    if not servers and platform == PLATFORM_OPNSENSE:
        ipsec = get_ipsec_config(root, platform)
        if ipsec:
            out(INFO, "No OpenVPN servers found — inspecting IPsec phase1 entries.")
            blank()
            for idx, p1 in enumerate(ipsec, 1):
                enc = p1.findtext("encryption-algorithm") or p1.findtext("iketype") or ""
                field(f"IPsec Phase1 #{idx}", p1.findtext("descr") or "(unnamed)")
                field("Encryption", enc or "(not set)")
                if "aes" in enc.lower() or "chacha" in enc.lower():
                    out(PASS, "Strong encryption detected in IPsec.")
                else:
                    out(WARN, "IPsec encryption may be weak — review manually.")
            return True

    if not servers:
        out(FAIL, "No OpenVPN or IPsec servers found.")
        return False

    secure_found = False
    for idx, server in enumerate(servers, 1):
        descr       = (server.findtext("description") or server.findtext("descr") or "").strip()
        mode        = (server.findtext("mode")         or "").strip()
        tls         = (server.findtext("tls")          or "").strip()
        tlsauth     = (server.findtext("tlsauth_enable") or "").strip()
        tls_version = (server.findtext("tlsversionmin") or "").strip()
        cipher      = normalize(server.findtext("crypto"))
        digest      = normalize(server.findtext("digest"))

        field(f"OpenVPN Server #{idx}", descr or "(unnamed)")
        field("Mode",        mode or "(not found)")
        field("TLS",         tls or "(not found)")
        field("TLS Auth",    tlsauth or "(not found)")
        field("TLS Version", tls_version or "(not set)")
        field("Cipher",      cipher or "(not set)")
        field("Digest",      digest or "(not set)")
        blank()

        tls_enabled = (
            bool(tls)
            or tlsauth.lower() in ("yes", "on", "1", "true")
            or mode.lower() == "server_tls"
        )

        if not tls_enabled:
            out(FAIL, "TLS protection not clearly detected.")
            blank()
            continue

        out(PASS, "TLS protection appears configured.")

        if tls_version in ("1.2", "1.3"):
            out(PASS, f"Strong TLS version detected ({tls_version}).")
        elif tls_version in ("1.0", "1.1"):
            out(FAIL, f"Weak TLS version detected ({tls_version}).")
        else:
            out(WARN, "TLS version not explicitly set.")

        if any(x in cipher for x in ("AES", "CHACHA20")):
            out(PASS, "Strong cipher detected.")
        else:
            out(WARN, "Cipher not recognized as strong.")

        if digest in ("SHA256", "SHA384", "SHA512"):
            out(PASS, "Strong digest detected.")
        elif digest in ("MD5", "SHA1"):
            out(FAIL, "Weak digest detected.")
        else:
            out(WARN, "Digest not recognized.")

        if tls_version in ("1.2", "1.3") and digest.startswith("SHA"):
            secure_found = True

        blank()

    if secure_found:
        out(PASS, "OpenVPN TLS configuration appears secure.")
        return True

    out(FAIL, "OpenVPN TLS configuration is NOT fully secure.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 5.5.1  Strong OpenVPN Crypto
# ─────────────────────────────────────────────────────────────────────────────

def check_5_5_1(root: ET.Element, platform: str) -> bool:
    section("5.5.1", "Ensure OpenVPN uses strong ciphers and hashing algorithms")
    out(INFO, "Objective : Enforce strong cryptography for all VPN tunnels.")
    blank()

    field("Platform", platform)
    blank()

    strong_ciphers = {"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
    weak_ciphers   = {"BF-CBC", "DES", "RC4", "3DES", "NULL"}
    strong_digests = {"SHA256", "SHA384", "SHA512"}
    weak_digests   = {"MD5", "SHA1"}

    servers = get_openvpn_servers(root, platform)

    # OPNsense IPsec fallback
    if not servers and platform == PLATFORM_OPNSENSE:
        ipsec = get_ipsec_config(root, platform)
        if ipsec:
            out(INFO, "No OpenVPN servers — checking IPsec crypto.")
            blank()
            overall = True
            for idx, p1 in enumerate(ipsec, 1):
                enc = (p1.findtext("encryption-algorithm") or "").upper()
                hash_ = (p1.findtext("hash-algorithm") or "").upper()
                field(f"IPsec #{idx} Encryption", enc or "(not set)")
                field(f"IPsec #{idx} Hash",       hash_ or "(not set)")
                if enc in weak_ciphers:
                    out(FAIL, f"Weak IPsec cipher: {enc}")
                    overall = False
                if hash_ in weak_digests:
                    out(FAIL, f"Weak IPsec hash: {hash_}")
                    overall = False
                blank()
            return overall
        out(FAIL, "No VPN servers found.")
        return False

    if not servers:
        out(FAIL, "No OpenVPN servers found.")
        return False

    secure_found = False
    for idx, s in enumerate(servers, 1):
        descr       = (s.findtext("description") or s.findtext("descr") or "").strip()
        cipher      = normalize(s.findtext("crypto"))
        digest      = normalize(s.findtext("digest"))
        tls_version = normalize(s.findtext("tlsversionmin"))
        ncp         = normalize(s.findtext("ncp-ciphers") or s.findtext("data-ciphers"))
        custom      = s.findtext("custom_options") or ""
        custom_ciphers = extract_custom_options(custom, "data-ciphers")
        tls_crypt   = "tls-crypt" in custom
        tls_auth    = "tls-auth" in custom

        field(f"OpenVPN Server #{idx}", descr or "(unnamed)")
        field("TLS Version",   tls_version or "(not set)")
        field("Cipher",        cipher or "(not set)")
        field("Digest",        digest or "(not set)")
        field("NCP Ciphers",   ncp or "(not set)")
        blank()

        issues = []

        if tls_version in ("1.0", "1.1"):
            issues.append(f"Weak TLS ({tls_version})")
            out(FAIL, f"Weak TLS version ({tls_version}).")
        elif tls_version in ("1.2", "1.3"):
            out(PASS, f"Strong TLS version ({tls_version}).")
        else:
            out(WARN, "TLS version not set.")

        if cipher in weak_ciphers:
            issues.append(f"Weak cipher ({cipher})")
            out(FAIL, f"Weak cipher ({cipher}).")
        elif cipher in strong_ciphers:
            out(PASS, "Strong cipher detected.")
        else:
            out(WARN, "Cipher not recognized.")

        if digest in weak_digests:
            issues.append(f"Weak digest ({digest})")
            out(FAIL, f"Weak digest ({digest}).")
        elif digest in strong_digests:
            out(PASS, "Strong digest detected.")
        else:
            out(WARN, "Digest not recognized.")

        if ncp:
            for c in [x.strip() for x in ncp.split(",")]:
                if c in weak_ciphers:
                    issues.append(f"Weak NCP cipher ({c})")
                    out(FAIL, f"Weak NCP cipher ({c}).")

        for c in custom_ciphers:
            if c in weak_ciphers:
                issues.append(f"Weak custom cipher ({c})")
                out(FAIL, f"Weak custom cipher ({c}).")

        if not (tls_crypt or tls_auth):
            issues.append("Missing tls-crypt/tls-auth")
            out(WARN, "No tls-crypt or tls-auth detected in custom options.")

        if not issues:
            secure_found = True
            out(PASS, "Strong cryptographic configuration detected.")
        else:
            out(FAIL, "Weak or insecure crypto configuration detected.")

        blank()

    if secure_found:
        out(PASS, "OpenVPN cryptographic configuration is secure.")
    else:
        out(FAIL, "OpenVPN cryptographic configuration is NOT secure.")
        remediation("Use AES-256-GCM or CHACHA20-POLY1305.")
        remediation("Use SHA256 or stronger digest.")
        remediation("Enforce TLS 1.2 or higher.")
        reference("CIS Benchmark — Section 5.5.1")

    return secure_found


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 6 — LOGGING  ════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 6.1  Syslog Configuration
# ─────────────────────────────────────────────────────────────────────────────

def check_6_1(root: ET.Element, platform: str) -> bool:
    section("6.1", "Ensure syslog is configured")
    out(INFO, "Objective : Ensure centralized logging is configured.")
    out(INFO,  "            Logs should be forwarded to a remote syslog server.")
    out(DETAIL,"Rationale : Centralized logging improves monitoring and incident response.")
    blank()

    field("Platform", platform)
    blank()

    syslog_cfg, source_label = get_syslog_config(root, platform)

    if syslog_cfg is None:
        out(FAIL, "No syslog configuration found.")
        remediation("Enable and configure remote syslog logging.")
        reference("CIS Benchmark — Section 6.1")
        return False

    field("Config Source", source_label)
    blank()

    if platform == PLATFORM_OPNSENSE:
        # OPNsense Syslog plugin uses different tag names
        # <OPNsense><Syslog><targets><target>…
        targets = syslog_cfg.findall(".//targets/target") or syslog_cfg.findall(".//target")
        remote_server = ""
        if targets:
            for t in targets:
                hostname = t.findtext("hostname") or t.findtext("host") or ""
                transport = t.findtext("transport") or ""
                level     = t.findtext("level") or ""
                if hostname:
                    remote_server = hostname
                    field("Remote Target",  hostname)
                    field("Transport",      transport or "(default)")
                    field("Level",          level or "(default)")
                    blank()

        # Fallback: simple remoteserver tag
        if not remote_server:
            remote_server = (
                syslog_cfg.findtext("remoteserver")
                or syslog_cfg.findtext("destination")
                or ""
            )
            field("Remote Syslog Server", remote_server or "(not configured)")

        filterlogs = syslog_cfg.findtext("filter") or syslog_cfg.findtext("firewall") or ""
        vpn_logs   = syslog_cfg.findtext("vpn")    or syslog_cfg.findtext("openvpn") or ""
        dhcp_logs  = syslog_cfg.findtext("dhcp")   or ""

        field("Firewall Logs", "Enabled" if is_enabled(filterlogs) else "Not Explicitly Enabled")
        field("VPN Logs",      "Enabled" if is_enabled(vpn_logs)   else "Not Explicitly Enabled")
        field("DHCP Logs",     "Enabled" if is_enabled(dhcp_logs)  else "Not Explicitly Enabled")
        blank()

    else:
        # pfSense
        remote_server = normalize_lower(syslog_cfg.findtext("remoteserver") or "")
        source_ip     = normalize_lower(syslog_cfg.findtext("sourceip") or "")
        filterlogs    = normalize_lower(syslog_cfg.findtext("filter") or "")
        dhcp          = normalize_lower(syslog_cfg.findtext("dhcp") or "")
        portal        = normalize_lower(syslog_cfg.findtext("portal") or "")
        vpn           = normalize_lower(syslog_cfg.findtext("vpn") or "")

        field("Remote Syslog Server", remote_server or "(not configured)")
        field("Source IP",            source_ip or "(default)")
        field("Firewall Logs",        "Enabled" if is_enabled(filterlogs) else "Not Explicitly Enabled")
        field("DHCP Logs",            "Enabled" if is_enabled(dhcp)       else "Not Explicitly Enabled")
        field("Portal Logs",          "Enabled" if is_enabled(portal)     else "Not Explicitly Enabled")
        field("VPN Logs",             "Enabled" if is_enabled(vpn)        else "Not Explicitly Enabled")
        blank()

    issues = []

    if not remote_server:
        issues.append("Remote syslog server not configured")
        out(FAIL, "No remote syslog server configured.")
    else:
        out(PASS, "Remote syslog server configured.")
        if ":6514" in remote_server:
            out(PASS, "Secure syslog port detected (6514/TLS).")
        elif ":514" in remote_server:
            out(WARN, "Standard syslog port (514/UDP) — consider TLS (6514).")
        elif remote_server:
            out(INFO, f"Syslog destination: {remote_server} — verify port/transport.")

    blank()

    if issues:
        out(FAIL, "Syslog configuration is incomplete.")
        remediation("Configure a remote syslog server for centralized log collection.")
        remediation("Use TLS syslog (port 6514) where possible for log integrity.")
        reference("CIS Benchmark — Section 6.1")
        return False

    out(PASS, "Syslog appears properly configured.")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# MAIN AUDIT RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def run_audit(config_file: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print()

    banner("CIS BENCHMARK — pfSense & OPNsense EXHAUSTIVE SECURITY AUDIT")
    banner("Sections 1 + 2 + 3 + 4 + 5 + 6")
    banner("GENERAL | USERS | PASSWORDS | FIREWALL | VPN | LOGGING")
    banner(f"File : {config_file}")
    banner(f"Time : {now}")

    try:
        tree = ET.parse(config_file)
        root = tree.getroot()
    except FileNotFoundError:
        print()
        out(FAIL, f"File not found: {config_file}")
        sys.exit(1)
    except ET.ParseError as exc:
        print()
        out(FAIL, f"XML parse error: {exc}")
        sys.exit(1)

    # ── Platform detection ──────────────────────────────────────────────────
    platform = detect_platform(root)
    blank()
    out(INFO, f"Detected platform : {C.BOLD}{platform}{C.RESET}")
    blank()

    version_raw, family, edition = determine_version(root, platform)

    out(DETAIL, "Device information from config:")
    field("Platform",       platform)
    field("Hostname",       root.findtext("./system/hostname") or "(not found)")
    field("Domain",         root.findtext("./system/domain")   or "(not found)")
    field("Config version", version_raw or "(not found)")
    field("Family",         family)
    field("Edition",        edition)

    results = {}

    # ────────────────────────────────────────────────────────────────────────
    blank()
    banner("SECTION 1 — GENERAL SETTING POLICY")
    results["1.1  SSH Warning Banner"]         = check_1_1(root, platform)
    results["1.2  AutoConfigBackup / Backup"]  = check_1_2(root, platform)
    results["1.3  MOTD"]                       = check_1_3(root, platform)
    results["1.4  Hostname"]                   = check_1_4(root, platform)
    results["1.5  DNS Servers"]                = check_1_5(root, platform)
    results["1.6  IPv6"]                       = check_1_6(root, platform)
    results["1.7  DNS Rebind Check"]           = check_1_7(root, platform)
    results["1.8  WebGUI HTTPS"]               = check_1_8(root, platform)
    results["1.9  High Availability / CARP"]   = check_1_9(root, platform)

    # ────────────────────────────────────────────────────────────────────────
    blank()
    banner("SECTION 2 — USERS MANAGEMENT")
    results["2.1  Session Timeout"]            = check_2_1(root, platform)
    results["2.2  LDAP / RADIUS"]             = check_2_2(root, platform)
    results["2.3  Console Password"]           = check_2_3(root, platform)
    results["2.4  Default Accounts"]           = check_2_4(root, platform)

    # ────────────────────────────────────────────────────────────────────────
    blank()
    banner("SECTION 3 — PASSWORD POLICY")
    results["3.1  Local Accounts"]             = check_3_1(root, platform)
    results["3.2  Login Threshold"]            = check_3_2(root, platform)
    results["3.3  Lockout Duration"]           = check_3_3(root, platform)
    results["3.4  Default Passwords"]          = check_3_4(root, platform)

    # ────────────────────────────────────────────────────────────────────────
    blank()
    banner("SECTION 4 — FIREWALL RULES POLICY")
    results["4.1.1 Destination Any"]           = check_4_1_1(root, platform)
    results["4.1.2 Source Any"]                = check_4_1_2(root, platform)
    results["4.1.3 Service Any"]               = check_4_1_3(root, platform)
    results["4.1.4 Unused Policies"]           = check_4_1_4(root, platform)
    results["4.1.5 Rule Logging"]              = check_4_1_5(root, platform)
    results["4.1.6 ICMP Security"]             = check_4_1_6(root, platform)

    # ────────────────────────────────────────────────────────────────────────
    blank()
    banner("SECTION 5 — INFRASTRUCTURE & VPN SECURITY")
    results["5.1.1 SNMP Trap Receivers"]       = check_5_1_1(root, platform)
    results["5.1.2 SNMP Traps Enabled"]        = check_5_1_2(root, platform)
    results["5.1.3 SNMP Secure Config"]        = check_5_1_3(root, platform)
    results["5.2.1 Timezone Configured"]       = check_5_2_1(root, platform)
    results["5.3.1 DNSSEC Enabled"]            = check_5_3_1(root, platform)
    results["5.4.1 RADIUS/LDAP for VPN"]       = check_5_4_1(root, platform)
    results["5.4.2 Trusted Certificate"]       = check_5_4_2(root, platform)
    results["5.4.3 OpenVPN TLS Encryption"]    = check_5_4_3(root, platform)
    results["5.5.1 Strong OpenVPN Crypto"]     = check_5_5_1(root, platform)

    # ────────────────────────────────────────────────────────────────────────
    blank()
    banner("SECTION 6 — LOGGING")
    results["6.1  Syslog Configuration"]       = check_6_1(root, platform)

    # ════════════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ════════════════════════════════════════════════════════════════════════
    blank()
    banner("FINAL AUDIT SUMMARY")
    blank()

    passed = sum(1 for v in results.values() if v)
    total  = len(results)

    for check, ok in results.items():
        status = PASS if ok else FAIL
        color  = STATUS_COLORS[status]
        print(f"  {color}{status}{RESET}  {check}")

    blank()
    percentage = int((passed / total) * 100)
    print(f"  Compliance Score : {passed}/{total} checks passed ({percentage}%)")
    blank()

    if passed == total:
        print(f"  {C.GREEN}✔ All {total} checks PASSED — configuration is COMPLIANT.{C.RESET}")
    else:
        failed = total - passed
        print(f"  {C.RED}✘ {failed}/{total} check(s) FAILED — remediation required.{C.RESET}")
        print("     Review FAIL / WARN findings and apply corrective actions immediately.")

    blank()
    line("═")
    print(f"  Audit completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    line("═")
    blank()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) == 2:
        config_path = sys.argv[1]
    else:
        config_path = input("Enter path to config.xml (pfSense or OPNsense): ").strip()
    run_audit(config_path)
