from __future__ import annotations

import argparse
from os import ST_APPEND
import queue
import signal
import subprocess
import threading
import time
from typing import Optional
import os
from pathlib import Path

from detector import HybridDetector, MLAnomalyDetector, RuleBasedDetector
from mitigator import Mitigator
from sniffer import DEFAULT_INTERFACE, PacketFeatures, interface_exists, start_sniffer


try:
    from colorama import Fore, Style, init  # type: ignore

    init(autoreset=True)

    SAFE_COLOR = Fore.GREEN + Style.BRIGHT
    RISKY_COLOR = Fore.RED + Style.BRIGHT
    INFO_COLOR = Fore.YELLOW + Style.BRIGHT
    RELESE_COLOR = Fore.BLUE + Style.BRIGHT
    RESET = Style.RESET_ALL
except Exception:
    SAFE_COLOR = "\033[92m\033[1m"
    RISKY_COLOR = "\033[91m\033[1m"
    INFO_COLOR = "\033[93m\033[1m"
    RELESE_COLOR = "\033[34m\033[1m"  # Fixed uppercase M typo
    RESET = "\033[0m"


def unified_release_device(ip: str, mitigator: Mitigator, quarantine_timers: dict, mac: Optional[str] = None) -> None:
    """
    CONSOLIDATED RELEASE FUNCTION:
    Wipes out kernel rules across source, destination, and hardware interfaces.
    """
    print(f"{INFO_COLOR}[UNIFIED RELEASE] Executing absolute clearance sequence for {ip}...{RESET}", flush=True)
    
    if mac:
        while True:
            p = subprocess.run(
                ["sudo", "iptables", "-D", "FORWARD", "-i", "ap0", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if p.returncode != 0:
                break

    while True:
        p = subprocess.run(
            ["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if p.returncode != 0:
            break
            
    while True:
        p = subprocess.run(
            ["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if p.returncode != 0:
            break

    try:
        mitigator.release_from_memory(ip, mac=mac)
    except Exception:
        pass

    quarantine_timers.pop(ip, None)


def manual_isolation_poller_loop(quarantine_timers: dict, stop_evt: threading.Event, args: argparse.Namespace) -> None:
    """
    BACKGROUND THREAD LOOP:
    Actively checks for manual jail tokens from Streamlit UI, applies firewall 
    blockades, and synchronizes state data into core dictionaries.
    """
    tmp_dir = Path("/tmp")
    
    while not stop_evt.is_set():
        time.sleep(0.5)  # Lightweight check window interval
        
        for token_file in tmp_dir.glob("manual_jail_*"):
            try:
                target_ip = token_file.name.replace("manual_jail_", "")
                
                # Check if device is already registered as restricted
                if target_ip in quarantine_timers:
                    token_file.unlink()
                    continue
                
                print(f"{RISKY_COLOR}[🚨 DASHBOARD MANUAL OVERRIDE] Isolating host target: {target_ip}{RESET}", flush=True)
                
                # 1. Inject Kernel Forwarding Layer Droppers
                subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", target_ip, "-j", "DROP"], check=True)
                subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-d", target_ip, "-j", "DROP"], check=True)
                
                # 2. Synchronize memory state data so timer evaluations track it correctly
                quarantine_timers[target_ip] = {
                    "expiry": time.time() + max(1, int(args.quarantine_secs)),
                    "cooldown_tail": time.time() + max(1, int(args.quarantine_secs)) + 2.0,
                    "mac": None,
                }
                
                token_file.unlink()
                print(f"{SAFE_COLOR}[SUCCESS] Manual containment applied cleanly for {target_ip}{RESET}", flush=True)
                
            except Exception as e:
                print(f"[ERROR] Failed to process UI manual isolation token: {e}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberShield: Real-time Network IDPS for a gateway interface.")
    parser.add_argument("--iface", default=DEFAULT_INTERFACE, help=f"Interface to sniff on (default: {DEFAULT_INTERFACE}).")
    parser.add_argument("--model", default="model.joblib", help="Path to IsolationForest joblib model.")
    parser.add_argument("--bpf", default="", help="Optional BPF capture filter (example: 'ip or ip6').")
    parser.add_argument("--log", default="security_log.csv", help="Path to CSV incident log.")
    parser.add_argument("--quarantine-secs", type=int, default=30, help="Seconds to quarantine a flagged IP (default: 30).")
    args = parser.parse_args()

    if not interface_exists(args.iface):
        raise SystemExit(f"Interface '{args.iface}' not found. Check `ip link` and hotspot interface name.")

    malicious_ips = ["203.0.113.66"]
    malicious_domains = ["malware.test", "bad.example"]

    detector = HybridDetector(
        rule_detector=RuleBasedDetector(malicious_ips=malicious_ips, malicious_domains=malicious_domains),
        ml_detector=MLAnomalyDetector(model_path=args.model, anomaly_threshold=-0.15),
    )
    mitigator = Mitigator(log_path=args.log)

    q: "queue.Queue[PacketFeatures]" = queue.Queue(maxsize=10000)
    stop_evt = threading.Event()
    quarantine_timers: dict[str, dict] = {}
    stats_lock = threading.Lock()
    total_scanned = 0
    safe_count = 0
    risky_count = 0

    def stop_flag() -> bool:
        return stop_evt.is_set()

    def on_features(f: PacketFeatures) -> None:
        nonlocal total_scanned
        with stats_lock:
            total_scanned += 1
        try:
            q.put_nowait(f)
        except queue.Full:
            return

    def print_summary_loop() -> None:
        nonlocal total_scanned, safe_count, risky_count
        while not stop_evt.is_set():
            time.sleep(5)
            if stop_evt.is_set():
                break
            with stats_lock:
                t = total_scanned
                s = safe_count
                r = risky_count
            print(
                f"{INFO_COLOR}[LIVE STATS] Total Packets: {t} | Safe: {s} | Threats Blocked: {r}{RESET}",
                flush=True,
            )

    def worker() -> None:
        nonlocal total_scanned, safe_count, risky_count
        while not stop_evt.is_set():
            try:
                f = q.get(timeout=0.2)
            except queue.Empty:
                pass
            else:
                try:
                    mitigator.log_traffic(f)
                    
                    if f.dst_ip in quarantine_timers and time.time() < quarantine_timers[f.dst_ip]["cooldown_tail"]:
                        continue

                    hit = detector.evaluate(f)

                    if hit is not None and hit.is_malicious:
                        ip_to_timer = hit.flagged_ip or f.dst_ip
                        
                        if ip_to_timer and ip_to_timer not in quarantine_timers:
                            with stats_lock:
                                risky_count += 1
                            
                            reason_lower = hit.reason.lower()
                            if "dos" in reason_lower or "ddos" in reason_lower or "flood" in reason_lower:
                                attack_type = "DoS/DDoS Attack"
                            elif "scan" in reason_lower or "port" in reason_lower:
                                attack_type = "Port Scanning"
                            elif "phish" in reason_lower or "malicious_ips" in reason_lower or "203.0.113.66" in f.dst_ip:
                                attack_type = "Phishing / Malicious Domain Access"
                            else:
                                attack_type = "Anomaly / Behavioral Intrusion"
                            score_txt = f" score={hit.score:.4f}" if hit.score is not None else ""
                            print(
                                f"{RISKY_COLOR}[ALARM / THREAT DETECTED]\n"
                                f" ├─ Target Device: {f.src_ip} -> {f.dst_ip}\n"
                                f" ├─ Classification: {attack_type}\n"
                                f" └─ Signature Info: {hit.reason}{score_txt}{RESET}",
                                flush=True,
                            )
                            
                            try:
                                mitigator.mitigate(hit)
                            except PermissionError:
                                mitigator.log_incident(hit)
                            
                            quarantine_timers[ip_to_timer] = {
                                "expiry": time.time() + max(1, int(args.quarantine_secs)),
                                "cooldown_tail": time.time() + max(1, int(args.quarantine_secs)) + 2.0,
                                "mac": hit.flagged_mac or getattr(f, 'src_mac', None),
                            }
                    else:
                        with stats_lock:
                            safe_count += 1
                finally:
                    q.task_done()

            # --- Smart Evaluation State Check Sync Loop ---
            now = time.time()
            tracked_ips = list(quarantine_timers.keys())

            for ip in tracked_ips:
                data = quarantine_timers.get(ip)
                if not data:
                    continue
                
                # 1. Check if the automatic timeout timer has expired
                time_expired = data["expiry"] <= now
                
                # 2. Check explicitly for the release token file dropped by the UI
                token_path = f"/tmp/release_{ip}"
                file_flag_exists = os.path.exists(token_path)
                
                # 3. Corrected manual evaluation guard: Only flag a manual release if the 
                # file token exists OR if it was an ML block that has been dropped from memory
                is_ml_block = data.get("mac") is not None
                memory_cleared = is_ml_block and hasattr(mitigator, '_blocked_ips') and (ip not in mitigator._blocked_ips)
                
                manually_released = file_flag_exists or memory_cleared

                # 4. Execute release only when genuinely ready
                if time_expired or manually_released:
                    try:
                        unified_release_device(ip, mitigator, quarantine_timers, mac=data.get("mac"))
                        
                        if os.path.exists(token_path):
                            try:
                                os.remove(token_path)
                            except Exception:
                                pass
                                
                        release_type = "automatically via timeout" if time_expired else "manually via dashboard"
                        print(f"{RELESE_COLOR}[SUCCESS] Quarantine cleanly lifted {release_type} for {ip}.{RESET}", flush=True)
                    
                    except Exception as e:
                        print(f"Error executing release sequence for {ip}: {e}", flush=True)

    def sniffer_thread() -> None:
        start_sniffer(interface=args.iface, on_features=on_features, stop_flag=stop_flag, bpf_filter=None)

    # Wire up the new dynamic manual signal tracker thread
    t_manual = threading.Thread(
        target=manual_isolation_poller_loop, 
        args=(quarantine_timers, stop_evt, args), 
        name="cybershield-manual-hook", 
        daemon=True
    )
    t_worker = threading.Thread(target=worker, name="cybershield-worker", daemon=True)
    t_sniff = threading.Thread(target=sniffer_thread, name="cybershield-sniffer", daemon=True)
    t_summary = threading.Thread(target=print_summary_loop, name="cybershield-summary", daemon=True)

    def _handle_sig(_sig: int, _frame: Optional[object]) -> None:
        stop_evt.set()

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    t_manual.start()
    t_worker.start()
    t_sniff.start()
    t_summary.start()

    print("CyberShield running smoothly with destination-specific release sync.")
    print("Press Ctrl+C to stop.")

    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    finally:
        stop_evt.set()
        t_sniff.join(timeout=1.0)
        t_worker.join(timeout=1.0)
        t_manual.join(timeout=1.0)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())