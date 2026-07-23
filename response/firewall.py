from __future__ import annotations

import ipaddress
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

blocked_ips = set()
RULE_COMMENT_PREFIX = "SecureOps"


class FirewallError(RuntimeError):
    pass


def validate_blockable_ip(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise FirewallError("Invalid IP address.") from exc

    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise FirewallError("Refusing to block unsafe local or multicast address.")

    return str(address)


def block_ip(ip: str) -> bool:
    try:
        ip = validate_blockable_ip(ip)

        if ip in blocked_ips or ip in list_blocked_ips():
            return False

        _run_iptables([
            "-A",
            "INPUT",
            "-s",
            ip,
            "-m",
            "comment",
            "--comment",
            f"{RULE_COMMENT_PREFIX}:{ip}",
            "-j",
            "DROP",
        ])

        blocked_ips.add(ip)

        logger.info("blocked ip=%s", ip)

        return True

    except Exception as exc:
        logger.warning("firewall block failed for ip=%s: %s", ip, exc)

        return False


def unblock_ip(ip: str) -> bool:
    ip = validate_blockable_ip(ip)
    if ip not in blocked_ips and ip not in list_blocked_ips():
        return False
    _run_iptables([
        "-D",
        "INPUT",
        "-s",
        ip,
        "-m",
        "comment",
        "--comment",
        f"{RULE_COMMENT_PREFIX}:{ip}",
        "-j",
        "DROP",
    ])
    blocked_ips.discard(ip)
    return True


def list_rules() -> list[str]:
    output = _run_iptables(["-S", "INPUT"], capture=True)
    return output.splitlines()


def list_blocked_ips() -> set[str]:
    ips = set()
    for line in list_rules():
        if RULE_COMMENT_PREFIX not in line or "-s " not in line:
            continue
        parts = line.split()
        for index, part in enumerate(parts):
            if part == "-s" and index + 1 < len(parts):
                ips.add(parts[index + 1].split("/", 1)[0])
    return ips


def clear_secureops_rules() -> int:
    removed = 0
    for ip in list(list_blocked_ips()):
        if unblock_ip(ip):
            removed += 1
    return removed


def _run_iptables(args: list[str], *, capture: bool = False) -> str:
    executable = "iptables"
    command = [executable, *args]
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        command.insert(0, "sudo")
    result = subprocess.run(
        command,
        check=True,
        capture_output=capture,
        text=True,
    )
    return result.stdout if capture else ""
