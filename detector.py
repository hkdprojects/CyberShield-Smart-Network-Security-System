from __future__ import annotations

# Keep network constants at the very top for safety/readability.
WHITELIST = {
    # Ubuntu VM
    #Update ubuntu vm's ip address

    #localhost
    "127.0.0.1", 
}

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Sequence, Set

import joblib
import math
import numpy as np
import time

from sniffer import PacketFeatures


BLACKLIST = {
    
    "203.0.113.66", # Explicit demo target signature
}


def is_whitelisted(ip: Optional[str]) -> bool:
    return ip is not None and ip in WHITELIST


def _pick_flagged_ip(f: PacketFeatures) -> str:
    """Identify the internal device IP initiating the traffic."""
    if is_whitelisted(f.src_ip):
        return f.dst_ip if f.dst_ip else "0.0.0.0"
    return f.src_ip if f.src_ip else "0.0.0.0"


def _pick_flagged_mac(f: PacketFeatures, flagged_ip: str) -> Optional[str]:
    if flagged_ip == f.src_ip:
        return getattr(f, 'src_mac', None)
    if flagged_ip == f.dst_ip:
        return getattr(f, 'dst_mac', None)
    return getattr(f, 'src_mac', None)


@dataclass(frozen=True)
class Detection:
    is_malicious: bool
    reason: str
    flagged_ip: Optional[str] = None
    flagged_mac: Optional[str] = None
    dns_qname: Optional[str] = None
    score: Optional[float] = None
    protocol: Optional[str] = None
    packet_count: Optional[int] = None
    packet_size: Optional[int] = None
    unique_dst_ports: Optional[int] = None
    entropy: Optional[float] = None


class RuleBasedDetector:
    def __init__(
        self,
        malicious_ips: Optional[Sequence[str]] = None,
        malicious_domains: Optional[Sequence[str]] = None,
    ) -> None:
        self.malicious_ips: Set[str] = set(malicious_ips or [])
        self.malicious_ips.update(BLACKLIST) # Merge standard blacklist definitions
        self.malicious_domains: Set[str] = set(d.lower().strip(".") for d in (malicious_domains or []))

    def evaluate(self, f: PacketFeatures) -> Optional[Detection]:
        # Direct signature monitoring lookup
        if f.dst_ip in self.malicious_ips or f.src_ip in self.malicious_ips:
            flagged_ip = _pick_flagged_ip(f)
            return Detection(
                is_malicious=True,
                reason=f"CRITICAL: Threat Intel Match - Rogue C&C Destination ({f.dst_ip if f.dst_ip in self.malicious_ips else f.src_ip})",
                flagged_ip=flagged_ip,
                flagged_mac=_pick_flagged_mac(f, flagged_ip),
                dns_qname=f.dns_qname,
                protocol=f.protocol,
                score=-0.6000, # Force a clear negative anomaly index line item
                packet_count=1,
                packet_size=int(f.packet_size),
                unique_dst_ports=1,
                entropy=0.0
            )

        if is_whitelisted(f.src_ip) or is_whitelisted(f.dst_ip):
            return None

        if f.dns_qname:
            q = f.dns_qname.lower().strip(".")
            for bad in self.malicious_domains:
                if q == bad or q.endswith("." + bad):
                    flagged_ip = _pick_flagged_ip(f)
                    return Detection(
                        is_malicious=True,
                        reason="rule: malicious DNS query",
                        flagged_ip=flagged_ip,
                        flagged_mac=_pick_flagged_mac(f, flagged_ip),
                        dns_qname=f.dns_qname,
                        protocol=f.protocol,
                        score=-1.0
                    )

        return None


@dataclass
class _FlowPacketRecord:
    ts: float
    size: int
    dst_port: int
    domain: Optional[str]


class MLAnomalyDetector:
    WINDOW_SECONDS = 5.0

    def __init__(
        self,
        model_path: str = "model.joblib",
        anomaly_threshold: float = 0.0,
    ) -> None:
        self.model_path = model_path
        self.anomaly_threshold = anomaly_threshold
        self.model = None
        self._seen_packets = 0
        self._flow_history: Dict[str, Deque[_FlowPacketRecord]] = defaultdict(deque)
        self._load_model()

    def _load_model(self) -> None:
        try:
            self.model = joblib.load(self.model_path)
        except Exception:
            self.model = None

    def _calculate_entropy(self, domain: str) -> float:
        if not domain:
            return 0.0
        counts = Counter(domain.lower())
        length = len(domain)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(entropy)

    def _prune_stale_records(self, src_ip: str, now: float) -> None:
        history = self._flow_history[src_ip]
        cutoff = now - self.WINDOW_SECONDS
        while history and history[0].ts < cutoff:
            history.popleft()

    def _append_packet(self, f: PacketFeatures, now: float) -> None:
        self._flow_history[f.src_ip].append(
            _FlowPacketRecord(
                ts=now,
                size=int(f.packet_size),
                dst_port=int(f.port),
                domain=f.dns_qname,
            )
        )

    def _compute_window_metrics(
        self, src_ip: str, current_packet: PacketFeatures
    ) -> tuple[int, int, int, float]:
        history = self._flow_history[src_ip]
        packet_count = len(history)
        packet_size = int(current_packet.packet_size)
        unique_dst_ports = len({rec.dst_port for rec in history})
        entropy = self._calculate_entropy(current_packet.dns_qname) if current_packet.dns_qname else 0.0
        return packet_count, packet_size, unique_dst_ports, entropy

    def featurize_flow(self, packet_count: int, packet_size: int, unique_dst_ports: int, entropy: float) -> np.ndarray:
        return np.array([packet_count, packet_size, unique_dst_ports, entropy], dtype=np.float64)

    def _behavioral_label(self, packet_count: int, packet_size: int, unique_dst_ports: int, entropy: float) -> str:
        if packet_count >= 800:
            return "ML ENGINE: DDoS Detected"
        if unique_dst_ports >= 20:
            return "ML ENGINE: Port Scan Detected"
        if entropy >= 3.5:
            return "ML ENGINE: Phishing Detected"
        return "ML ENGINE: Anomaly Detected"

    def evaluate(self, f: PacketFeatures) -> Optional[Detection]:
        if is_whitelisted(f.src_ip) or is_whitelisted(f.dst_ip):
            return None

        if self.model is None:
            return None

        try:
            now = time.time()
            src_ip = f.src_ip

            self._prune_stale_records(src_ip, now)
            self._append_packet(f, now)

            packet_count, packet_size, unique_dst_ports, entropy = self._compute_window_metrics(src_ip, f)

            x = self.featurize_flow(packet_count, packet_size, unique_dst_ports, entropy).reshape(1, -1)
            score = float(self.model.decision_function(x)[0])
            pred = int(self.model.predict(x)[0])

            self._seen_packets += 1
            if self._seen_packets % 10 == 0:
                label = "Normal" if pred == 1 else "Anomaly"
                print(f"[ML PROFILE] Window=({packet_count} pkts, size={packet_size}B) score={score:.4f} ({label})", flush=True)

            if not (pred == -1 or score < self.anomaly_threshold):
                return None

            reason = self._behavioral_label(packet_count, packet_size, unique_dst_ports, entropy)
            flagged_ip = _pick_flagged_ip(f)
            
            return Detection(
                is_malicious=True,
                reason=reason,
                flagged_ip=flagged_ip,
                flagged_mac=_pick_flagged_mac(f, flagged_ip),
                dns_qname=f.dns_qname,
                score=score,
                protocol=f.protocol,
                packet_count=packet_count,
                packet_size=packet_size,
                unique_dst_ports=unique_dst_ports,
                entropy=entropy
            )
        except Exception:
            return None


class HybridDetector:
    def __init__(self, rule_detector: RuleBasedDetector, ml_detector: MLAnomalyDetector) -> None:
        self.rule_detector = rule_detector
        self.ml_detector = ml_detector

    def evaluate(self, f: PacketFeatures) -> Optional[Detection]:
        if is_whitelisted(f.src_ip) or is_whitelisted(f.dst_ip):
            return None

        # Inclusive check: allows tracking all interfaces handling local subnets (192.168.x.x / 10.x.x.x)
        is_relevant = (
            f.src_ip.startswith("10.") or f.src_ip.startswith("192.168.") or
            f.dst_ip.startswith("10.") or f.dst_ip.startswith("192.168.") or
            f.dst_ip == "203.0.113.66"
        )
        if not is_relevant:
            return None

        # Run fast structural alert signature validation
        hit = self.rule_detector.evaluate(f)
        if hit:
            return hit
            
        return self.ml_detector.evaluate(f)