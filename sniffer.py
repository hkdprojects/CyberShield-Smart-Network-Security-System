from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from scapy.all import DNS, DNSQR, Ether, IP, IPv6, TCP, UDP, conf, sniff  # type: ignore


DEFAULT_INTERFACE = "ap0" #any other created by hotspot


@dataclass(frozen=True)
class PacketFeatures:
    src_ip: str
    dst_ip: str
    src_mac: Optional[str]
    dst_mac: Optional[str]
    port: int
    packet_size: int
    protocol: str
    dns_qname: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "port": self.port,
            "packet_size": self.packet_size,
            "protocol": self.protocol,
            "dns_qname": self.dns_qname,
        }


def _safe_len(pkt: Any) -> int:
    try:
        return len(bytes(pkt))
    except Exception:
        try:
            return len(pkt)
        except Exception:
            return 0


def _get_ip_pair(pkt: Any) -> tuple[str, str, str]:
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst, "IPv4"
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst, "IPv6"
    return "0.0.0.0", "0.0.0.0", "L2"


def _get_mac_pair(pkt: Any) -> tuple[Optional[str], Optional[str]]:
    if Ether in pkt:
        return pkt[Ether].src, pkt[Ether].dst
    return None, None


def _get_l4_port_and_proto(pkt: Any) -> tuple[int, str]:
    if TCP in pkt:
        p = pkt[TCP].dport
        return int(p) if p is not None else 0, "TCP"
    if UDP in pkt:
        p = pkt[UDP].dport
        return int(p) if p is not None else 0, "UDP"
    return 0, "OTHER"


def _get_dns_qname(pkt: Any) -> Optional[str]:
    """
    Extract a DNS question name (qname) when available.
    Note: only present for DNS query packets (typically UDP/53).
    """
    try:
        if DNS in pkt and pkt[DNS].qd is not None and DNSQR in pkt:
            raw = pkt[DNSQR].qname
            if raw is None:
                return None
            if isinstance(raw, (bytes, bytearray)):
                return raw.decode(errors="ignore").rstrip(".")
            return str(raw).rstrip(".")
    except Exception:
        return None
    return None


def extract_features(pkt: Any) -> PacketFeatures:
    src_ip, dst_ip, _ip_ver = _get_ip_pair(pkt)
    src_mac, dst_mac = _get_mac_pair(pkt)
    port, proto = _get_l4_port_and_proto(pkt)
    size = _safe_len(pkt)
    dns_qname = _get_dns_qname(pkt)

    return PacketFeatures(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=src_mac,
        dst_mac=dst_mac,
        port=port,
        packet_size=size,
        protocol=proto,
        dns_qname=dns_qname,
    )


def require_root_for_sniffing() -> None:
    """
    On Ubuntu/Linux, sniffing raw packets typically requires root.
    """
    try:
        if os.geteuid() != 0:
            raise PermissionError(
                "Root privileges required for packet sniffing. "
                "Run with: sudo -E python3 main.py"
            )
    except AttributeError:
        # Non-POSIX platforms (not expected here)
        return


def get_interface_ip(interface: str) -> Optional[str]:
    """
    Best-effort: return the IPv4 address assigned to `interface` on Linux.

    This is used to exclude the local machine's traffic so CyberShield doesn't
    flag/quarantine itself (e.g., NAT/gateway flows).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        import fcntl  # Linux/POSIX only
        ifreq = struct.pack("256s", interface.encode("utf-8")[:15])
        res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)
        return socket.inet_ntoa(res[20:24])
    except Exception:
        import subprocess

        out = subprocess.check_output(["ip", "-4", "addr", "show", interface]).decode()
        import re

        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
        return match.group(1) if match else None
    finally:
        try:
            s.close()
        except Exception:
            pass


def build_bpf_excluding_local(interface: str, user_bpf: Optional[str] = None) -> Optional[str]:
    """
    Build a BPF filter that excludes traffic to/from the local interface IP.

    Example result: "(not host 192.168.12.1) and (ip or ip6)"
    """
    local_ip = get_interface_ip(interface)
    user = (user_bpf or "").strip()

    if local_ip:
        excl = f"not host {local_ip}"
        if user:
            return f"({excl}) and ({user})"
        return excl

    # If we can't determine local IP, fall back to user filter as-is.
    return user if user else None


def start_sniffer(
    interface: str,
    on_features: Callable[[PacketFeatures], None],
    stop_flag: Callable[[], bool],
    bpf_filter: Optional[str] = None,
) -> None:
    """
    Real-time packet capture engine (Scapy).

    - **interface**: typically 'wlan0' for the Wi-Fi hotspot interface.
    - **on_features**: callback invoked per packet with extracted features.
    - **stop_flag**: function returning True to stop sniffing.
    - **bpf_filter**: optional BPF string (e.g., 'ip or ip6').
    """
    require_root_for_sniffing()

    GREEN = "\033[92m"
    RESET = "\033[0m"

    def _handle(pkt: Any) -> None:
        print("DEBUG: Captured a packet!", flush=True)
        if stop_flag():
            return
        try:
            feats = extract_features(pkt)
            # Basic sanity guard: ignore empty/unknown traffic
            if feats.packet_size <= 0:
                return
            # Print every packet immediately (flush=True) for real-time visibility.
            print(
                f"{GREEN}[PACKET]{RESET} Source: {feats.src_ip} -> Dest: {feats.dst_ip} | "
                f"Protocol: {feats.protocol} | Size: {feats.packet_size}",
                flush=True,
            )
            on_features(feats)
        except Exception:
            # Avoid crashing the sniffer thread on malformed packets
            return

    # Layer-2 sniffing via Scapy's L2socket is often more reliable in VMs.
    # Also: store=0 disables buffering/storage; no BPF filters (capture everything).
    l2 = conf.L2socket(iface=interface)
    try:
        sniff(
            opened_socket=l2,
            prn=_handle,
            store=0,
            stop_filter=lambda _pkt: stop_flag(),
        )
    finally:
        try:
            l2.close()
        except Exception:
            pass


def interface_exists(interface: str) -> bool:
    """
    Best-effort check that the interface name exists.
    """
    try:
        socket.if_nametoindex(interface)
        return True
    except OSError:
        return False
