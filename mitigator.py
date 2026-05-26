from __future__ import annotations

import csv
import os
import subprocess
import time
from pathlib import Path
from typing import Optional, Set

from detector import Detection, is_whitelisted
from sniffer import PacketFeatures

# Stable CSV schema for security_log.csv (dashboard reads these columns)
SECURITY_LOG_FIELDS = [
    "timestamp",
    "is_malicious",
    "reason",
    "flagged_ip",
    "flagged_mac",
    "dns_qname",
    "score",
    "protocol",
    "packet_count",
    "packet_size",
    "unique_dst_ports",
    "entropy",
]


class Mitigator:
    """
    Executes mitigations:
    - desktop notification (notify-send)
    - quarantine via iptables (DROP)
    - log incidents to security_log.csv

    NOTE: iptables changes require root on Ubuntu.
    """

    def __init__(self, log_path: str = "security_log.csv") -> None:
        self.log_path = Path(log_path)
        self.traffic_log_path = Path("traffic_log.csv")
        self._blocked_ips: Set[str] = set()
        self._blocked_macs: Set[str] = set()

    @staticmethod
    def _require_root_for_iptables() -> None:
        if os.geteuid() != 0:
            raise PermissionError(
                "Root privileges required for iptables. "
                "Run with: sudo -E python3 main.py"
            )

    @staticmethod
    def _run(cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def send_notification(self, title: str, message: str) -> None:
        try:
            self._run(["notify-send", title, message])
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _iptables_drop_ip(self, ip: str) -> None:
        self._require_root_for_iptables()
        # FIX: Removed hardcoded old test subnets. Clean surgical isolation blocks.
        self._run(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
        self._run(["sudo", "iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"])

    def _iptables_drop_mac(self, mac: str) -> None:
        self._require_root_for_iptables()
        # FIX: Cleared destination exceptions to guarantee total Layer-2 device jail when triggered
        cmd = [
            "iptables",
            "-I",
            "FORWARD",
            "-i",
            "ap0",
            "-m",
            "mac",
            "--mac-source",
            mac,
            "-j",
            "DROP",
        ]
        self._run(cmd)

    def quarantine(self, ip: Optional[str], mac: Optional[str]) -> None:
        """
        Quarantine by IP and/or MAC. Deduplicated per runtime.
        Never blocks whitelisted IPs.
        """
        if ip:
            if is_whitelisted(ip):
                return
            if ip not in self._blocked_ips:
                self._iptables_drop_ip(ip)
                self._blocked_ips.add(ip)

        if mac and mac not in self._blocked_macs:
            self._iptables_drop_mac(mac)
            self._blocked_macs.add(mac)

    def release_from_memory(self, ip: Optional[str], mac: Optional[str] = None) -> None:
        """
        Clears the tracking memory so the IDPS can block this device again 
        if it commits another infraction.
        """
        if ip and ip in self._blocked_ips:
            self._blocked_ips.discard(ip)
        if mac and mac in self._blocked_macs:
            self._blocked_macs.discard(mac)
        print(f"[MEMORY CLEANUP] Forgot block state for IP: {ip} | MAC: {mac}", flush=True)
        
    def log_incident(self, detection: Detection) -> None:
        """
        Append an incident line to security_log.csv (dashboard-safe schema).
        """
        if detection is None:
            return

        row = {
            "timestamp": int(time.time()),
            "is_malicious": bool(getattr(detection, "is_malicious", False)),
            "reason": getattr(detection, "reason", None) or "unknown",
            "flagged_ip": getattr(detection, "flagged_ip", None) or "",
            "flagged_mac": getattr(detection, "flagged_mac", None) or "",
            "dns_qname": getattr(detection, "dns_qname", None) or "",
            "score": getattr(detection, "score", None),
            "protocol": getattr(detection, "protocol", None) or "",
            "packet_count": getattr(detection, "packet_count", None),
            "packet_size": getattr(detection, "packet_size", None),
            "unique_dst_ports": getattr(detection, "unique_dst_ports", None),
            "entropy": getattr(detection, "entropy", None),
        }

        write_header = not self.log_path.exists()
        try:
            with self.log_path.open("a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=SECURITY_LOG_FIELDS, extrasaction="ignore")
                if write_header:
                    writer.writeheader()
                writer.writerow(row)
        except Exception:
            pass

    def log_traffic(self, features: PacketFeatures) -> None:
        """
        Append every captured packet's features to traffic_log.csv for dashboards.
        """
        if features is None:
            return

        row = {
            "timestamp": int(time.time()),
            "src_ip": getattr(features, "src_ip", "") or "",
            "dst_ip": getattr(features, "dst_ip", "") or "",
            "protocol": getattr(features, "protocol", "") or "",
            "port": getattr(features, "port", 0),
            "packet_size": getattr(features, "packet_size", 0),
        }

        fields = list(row.keys())
        write_header = not self.traffic_log_path.exists()
        try:
            with self.traffic_log_path.open("a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                if write_header:
                    writer.writeheader()
                writer.writerow(row)
        except Exception:
            pass

    def mitigate(self, detection: Optional[Detection]) -> None:
        """
        Full mitigation pipeline: notify → quarantine → log.
        Safe against None or partially filled Detection objects.
        """
        if detection is None or not getattr(detection, "is_malicious", False):
            return

        reason = getattr(detection, "reason", None) or "Threat detected"
        flagged_ip = getattr(detection, "flagged_ip", None) or "-"
        flagged_mac = getattr(detection, "flagged_mac", None) or "-"

        title = "CyberShield: Threat detected"
        msg = f"{reason}\nIP={flagged_ip} MAC={flagged_mac}"
        dns_qname = getattr(detection, "dns_qname", None)
        if dns_qname:
            msg += f"\nDNS={dns_qname}"
        score = getattr(detection, "score", None)
        if score is not None:
            try:
                msg += f"\nScore={float(score):.4f}"
            except (TypeError, ValueError):
                pass

        self.send_notification(title, msg)

        try:
            self.quarantine(
                getattr(detection, "flagged_ip", None),
                getattr(detection, "flagged_mac", None),
            )
        except PermissionError:
            raise

        self.log_incident(detection)