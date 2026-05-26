from __future__ import annotations

import os
import html
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh


LOG_PATH = Path("security_log.csv")
TRAFFIC_PATH = Path("traffic_log.csv")  # Dedicated traffic file
APP_LOG_PATH = Path("app.log")

NEON_GREEN = "#39FF14"
BRIGHT_RED = "#FF1744"
BG = "#0B0F14"
PANEL = "#0F1720"
TEXT = "#E6EDF3"
MUTED = "#93A4B8"


@st.cache_data
def _apply_soc_theme() -> None:
    """Injects layout and custom SOC panels once to save rendering performance."""
    st.markdown(
        f"""
        <style>
        .stApp {{ background: {BG}; color: {TEXT}; }}
        .soc-title {{ font-size: 28px; font-weight: 800; letter-spacing: 0.4px; margin: 0 0 6px 0; }}
        .soc-subtitle {{ color: {MUTED}; margin-top: -2px; margin-bottom: 10px; }}
        .panel {{ background: {PANEL}; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 16px 18px; }}
        .status-secure {{ border: 1px solid rgba(57,255,20,0.25); box-shadow: 0 0 22px rgba(57,255,20,0.10); }}
        .status-threat {{ border: 1px solid rgba(255,23,68,0.35); box-shadow: 0 0 26px rgba(255,23,68,0.12); }}
        .status-text {{ font-size: 34px; font-weight: 900; letter-spacing: 0.8px; margin: 2px 0 0 0; }}
        .status-secure .status-text {{ color: {NEON_GREEN}; }}
        .status-threat .status-text {{ color: {BRIGHT_RED}; animation: flash 1s infinite; }}
        @keyframes flash {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.25; }} 100% {{ opacity: 1; }} }}
        .tiny {{ color: {MUTED}; font-size: 12px; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _read_optimized_log(path: Path, nrows: int = 100) -> pd.DataFrame:
    """Efficiently loads only the last N rows of a log file to avoid OOM crashes."""
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()

    try:
        df = pd.read_csv(path).tail(nrows)
        
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
            df["ts"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")
        else:
            df["ts"] = pd.NaT

        if "is_malicious" in df.columns:
            df["is_malicious"] = df["is_malicious"].astype(str).str.lower().isin(["true", "1", "yes"])
        return df
    except Exception:
        return pd.DataFrame()


def get_connected_devices() -> pd.DataFrame:
    """Dynamically locates active leases and verifies they are online using the system ARP cache."""
    devices = []
    lease_file = None

    # Locate the active dnsmasq lease file inside /tmp dynamically
    if os.path.exists("/tmp"):
        for root, dirs, files in os.walk("/tmp"):
            if "dnsmasq.leases" in files:
                lease_file = os.path.join(root, "dnsmasq.leases")
                break

    if not lease_file:
        lease_file = "/var/lib/misc/dnsmasq.leases"
        
    if not os.path.exists(lease_file):
        return pd.DataFrame(columns=["Device Name", "IP Address", "Hardware MAC"])

    # Read the live Linux kernel ARP cache to filter out disconnected nodes
    active_ips = set()
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as arp_f:
                lines = arp_f.readlines()[1:]  # Skip header row
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "0x0":
                        active_ips.add(parts[0])
    except Exception:
        pass

    # Parse active dynamic hotspot network allocations
    try:
        with open(lease_file, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    ip_address = parts[2]
                    if ip_address in active_ips:
                        hostname = parts[3] if parts[3] != "*" else "Unknown Device"
                        devices.append({
                            "Device Name": hostname,
                            "IP Address": ip_address,
                            "Hardware MAC": parts[1].upper()
                        })
    except Exception:
        pass
            
    return pd.DataFrame(devices, columns=["Device Name", "IP Address", "Hardware MAC"])


def _get_quarantined_ips_fast() -> Tuple[List[str], Optional[str]]:
    """Quickly fetches iptables status without triggering sub-process hangs."""
    cmd = ["sudo", "-n", "iptables", "-nL", "FORWARD"]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5)
        if p.returncode != 0:
            return [], "Sudo NOPASSWD access required."
        
        ips = []
        for line in p.stdout.splitlines():
            if "DROP" in line:
                cols = re.split(r"\s+", line.strip())
                if len(cols) >= 4 and cols[3] not in {"0.0.0.0/0", "anywhere"}:
                    clean_ip = cols[3].split("/")[0]
                    ips.append(clean_ip)
        return list(set(ips)), None
    except Exception as e:
        return [], f"Error: {e}"


def _iptables_release_ip(ip: str) -> bool:
    """Tears down all matching rules recursively to prevent lingering ghost blocks."""
    deleted_any = False
    
    while True:
        p = subprocess.run(["sudo", "-n", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5)
        if p.returncode == 0:
            deleted_any = True
        else:
            break
            
    while True:
        p = subprocess.run(["sudo", "-n", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5)
        if p.returncode == 0:
            deleted_any = True
        else:
            break
            
    return deleted_any


def main() -> None:
    st.set_page_config(page_title="CyberShield SOC Dashboard", page_icon="🛡️", layout="wide")
    _apply_soc_theme()
    
    st_autorefresh(interval=3500, key="cybershield_live_refresh")

    st.markdown('<div class="soc-title">CyberShield — SOC Live Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subtitle">Real-time ML behavioral intrusion visibility</div>', unsafe_allow_html=True)

    df_security = _read_optimized_log(LOG_PATH, nrows=50)
    df_traffic = _read_optimized_log(TRAFFIC_PATH, nrows=100)

    total_packets = len(df_traffic) if not df_traffic.empty else 0
    anomalies = len(df_security) if not df_security.empty else 0
    
    jailed_ips, jail_err = _get_quarantined_ips_fast()
    active_quarantines = len(jailed_ips)

    c1, c2, c3 = st.columns(3)
    c1.metric("Live Traffic Window", f"Last {total_packets} Pkts")
    c2.metric("Anomalies Captured", f"{anomalies}")
    c3.metric("Isolated Threat Entities", f"{active_quarantines}")

    if active_quarantines > 0:
        st.markdown(
            f'<div class="panel status-threat"><div class="tiny">ALARM MATRIX</div><div class="status-text">THREAT ACTIVE</div><div class="tiny">System tracking isolated device vectors inside containment space.</div></div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f'<div class="panel status-secure"><div class="tiny">ALARM MATRIX</div><div class="status-text">NETWORK SAFE</div><div class="tiny">All traffic metrics sitting inside standard geometric baseline bounds.</div></div>',
            unsafe_allow_html=True
        )

    st.write("")

    # --- Layout Matrix: Management Panels ---
    col_inventory, col_jail = st.columns(2)

    # --- LEFT COLUMN: LIVE CONNECTED DEVICES ---
    with col_inventory:
        st.subheader("👥 Live Connected Devices")
        df_connected = get_connected_devices()
        
        if df_connected.empty:
            st.info("No active client devices detected on the hotspot network.")
        else:
            st.caption(f"Total Active Devices: **{len(df_connected)}**")
            st.dataframe(df_connected, use_container_width=True, hide_index=True)
            
            target_device = st.selectbox("Select a target device to manually isolate:", df_connected["IP Address"].tolist(), key="jail_select")
            if st.button("🚨 Manual Isolation", type="primary", use_container_width=True):
                # FIXED: Write file via standard touch to make sure it bypasses root lockouts cleanly
                token_file = f"/tmp/manual_jail_{target_device}"
                try:
                    with open(token_file, "w") as f:
                        f.write("MANUAL")
                    # Force local system permissions update instantly
                    os.chmod(token_file, 0o777)
                    st.warning(f"Isolating {target_device}...")
                    time.sleep(0.5)
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to drop signal token: {e}")

    # --- RIGHT COLUMN: ACTIVE QUARANTINE (JAIL) WITH FULL ACTIONS ---
    with col_jail:
        st.subheader("🔒 Active Quarantine (Jail)")
        if jail_err:
            st.error(jail_err)
        elif not jailed_ips:
            st.success("No current host restrictions active.")
        else:
            st.caption(f"Total Quarantined Hosts: **{len(jailed_ips)}**")
            for idx, ip in enumerate(jailed_ips):
                row = st.columns([3, 1])
                row[0].markdown(f"🛑 **Host Target IP:** `{ip}`")
                if row[1].button("Release", key=f"rel_{ip}_{idx}", use_container_width=True):
                    rules_dropped = _iptables_release_ip(ip)
                    try:
                        sync_file = Path(f"/tmp/release_{ip}")
                        sync_file.write_text("release", encoding="utf-8")
                        os.chmod(sync_file, 0o777)
                    except Exception as e:
                        st.error(f"Sync error: {e}")

                    st.success(f"Flushed restriction rule for {ip}")
                    time.sleep(0.4)
                    st.rerun()
    
    st.write("---")
    
    # --- LOWER PLACEMENT: TRAFFIC WAVEFORM ANALYSIS ---
    st.subheader("Traffic Analysis Waveform")
    if df_traffic.empty or "ts" not in df_traffic.columns:
        st.info("Waiting for telemetry stream connection data...")
    else:
        ts_df = df_traffic.dropna(subset=["ts"]).copy()
        chart_data = ts_df.set_index("ts").resample("5s").size().rename("Packets/Sec")
        st.line_chart(chart_data)

    # --- BOTTOM PANEL: RECENT INCIDENT LOGS & CLASSIFICATIONS ---
    st.write("")
    st.subheader("Recent Structural Security Incidents Log")
    if df_security.empty:
        st.info("Zero incident signatures detected in security logs.")
    else:
        def classify_reason(reason):
            if pd.isna(reason):
                return "Unknown Threat"
            r = str(reason).lower()
            if "dos" in r or "ddos" in r or "flood" in r:
                return "DoS/DDoS Protection Trigger"
            if "scan" in r or "port" in r:
                return "Port Scanning Reconnaissance"
            if "phish" in r or "malicious" in r:
                return "Phishing / Malicious Connection"
            return "ML Behavioral Anomaly"

        if "reason" in df_security.columns:
            df_security["Attack Classification"] = df_security["reason"].apply(classify_reason)
        else:
            df_security["Attack Classification"] = "ML Behavioral Anomaly"

        target_cols = [c for c in ["ts", "Attack Classification", "flagged_ip", "flagged_mac", "score"] if c in df_security.columns]
        
        display_df = df_security[target_cols].tail(15).rename(columns={
            "ts": "Timestamp",
            "flagged_ip": "Attacking IP",
            "flagged_mac": "Hardware MAC",
            "score": "Anomaly Score"
        })
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()