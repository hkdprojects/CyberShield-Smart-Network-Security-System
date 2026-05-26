from __future__ import annotations

import argparse
import math
import random
import string
from collections import Counter
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------------------------
# Shannon entropy for domain strings (benign vs phishing)
# ---------------------------------------------------------------------------

LOW_ENTROPY_DOMAINS: List[str] = [
    "google.com",
    "amazon.com",
    "bbc.co.uk",
    "github.com",
    "ubuntu.com",
    "microsoft.com",
    "cloudflare.com",
    "wikipedia.org",
]

PHISHING_DOMAIN_TEMPLATES: List[str] = [
    "free-xiaomi-rewards-claim-login.link",
    "secure-paypa1-verify-account.top",
    "apple-id-locked-update-now.xyz",
    "crypto-airdrop-claim-wallet-verify.io",
    "netflix-billing-failed-update.card",
    "microsoft-365-password-reset-urgent.support",
]

STANDARD_PORTS = [80, 443, 53, 123, 22]


def domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    counts = Counter(domain.lower())
    length = len(domain)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def _random_phishing_domain(rng: random.Random) -> str:
    prefixes = ["secure", "free", "verify", "update", "claim", "login"]
    brands = ["paypa1", "apple-id", "microsoft", "amazon", "netflix"]
    suffixes = ["link", "top", "xyz", "io", "support", "card"]
    return (
        f"{rng.choice(prefixes)}-{rng.choice(brands)}-"
        f"{''.join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(5, 12)))}."
        f"{rng.choice(suffixes)}"
    )


def _flow_row(
    profile: str,
    packet_count: int,
    packet_size: float,
    unique_dst_ports: int,
    domain: str,
) -> dict:
    return {
        "profile": profile,
        "packet_count": int(packet_count),
        "packet_size": float(packet_size),
        "unique_dst_ports": int(unique_dst_ports),
        "domain": domain,
        "entropy": domain_entropy(domain),
    }


def _generate_normal_flows(n: int, rng: random.Random) -> List[dict]:
    """
    FIXED: Real-world network MTU profile simulation.
    Expands the packet size limits to 1500 bytes to accommodate large 
    streaming payloads (like the 1294 byte Google/Meta UDP traffic).
    """
    rows: List[dict] = []
    for _ in range(n):
        rows.append(
            _flow_row(
                profile="normal",
                packet_count=rng.randint(1, 50), # Expanded window for burst traffic
                packet_size=float(np.clip(rng.gauss(850, 250), 40, 1500)), # Perfectly maps 1294-sized blocks
                unique_dst_ports=rng.randint(1, 3),
                domain=rng.choice(LOW_ENTROPY_DOMAINS),
            )
        )
    return rows


def _generate_ddos_flows(n: int, rng: random.Random) -> List[dict]:
    rows: List[dict] = []
    for _ in range(n):
        rows.append(
            _flow_row(
                profile="ddos",
                packet_count=rng.randint(800, 2500),
                packet_size=float(rng.randint(64, 120)),
                unique_dst_ports=1,
                domain=f"flood-{rng.choice(STANDARD_PORTS)}.internal",
            )
        )
    return rows


def _generate_port_scan_flows(n: int, rng: random.Random) -> List[dict]:
    rows: List[dict] = []
    for _ in range(n):
        rows.append(
            _flow_row(
                profile="port_scan",
                packet_count=rng.randint(1, 3),
                packet_size=float(rng.randint(40, 128)),
                unique_dst_ports=rng.randint(20, 150),
                domain=rng.choice(["scan.local", "recon.internal", "nmap.probe"]),
            )
        )
    return rows


def _generate_phishing_flows(n: int, rng: random.Random) -> List[dict]:
    rows: List[dict] = []
    for _ in range(n):
        domain = (
            rng.choice(PHISHING_DOMAIN_TEMPLATES)
            if rng.random() < 0.6
            else _random_phishing_domain(rng)
        )
        rows.append(
            _flow_row(
                profile="phishing",
                packet_count=rng.randint(2, 18),
                packet_size=float(np.clip(rng.gauss(520, 150), 128, 900)),
                unique_dst_ports=rng.randint(1, 2),
                domain=domain,
            )
        )
    return rows


def generate_synthetic_normal(n: int, seed: int) -> pd.DataFrame:
    rng = random.Random(seed)
    np.random.seed(seed)

    n_normal = int(n * 0.85)  # Boost normal allocation ratio
    n_ddos = int(n * 0.05)
    n_port_scan = int(n * 0.05)
    n_phishing = int(n * 0.05)
    remainder = n - (n_normal + n_ddos + n_port_scan + n_phishing)
    n_normal += remainder

    print("=" * 64)
    print("CyberShield — Tuned Flow Training Data")
    print("=" * 64)
    print(f"Total flows : {n}")
    print(f"  Normal     : {n_normal:5d}  ({100 * n_normal / n:5.1f}%)")
    print(f"  DDoS       : {n_ddos:5d}  ({100 * n_ddos / n:5.1f}%)")
    print(f"  Port scan  : {n_port_scan:5d}  ({100 * n_port_scan / n:5.1f}%)")
    print(f"  Phishing   : {n_phishing:5d}  ({100 * n_phishing / n:5.1f}%)")
    print("-" * 64)

    rows: List[dict] = []
    rows.extend(_generate_normal_flows(n_normal, rng))
    rows.extend(_generate_ddos_flows(n_ddos, rng))
    rows.extend(_generate_port_scan_flows(n_port_scan, rng))
    rows.extend(_generate_phishing_flows(n_phishing, rng))

    rng.shuffle(rows)
    df = pd.DataFrame(rows)

    feature_cols = ["packet_count", "packet_size", "unique_dst_ports", "entropy"]
    print("Profile means:")
    for profile, grp in df.groupby("profile"):
        print(
            f"  {profile:10s}  pkts={grp['packet_count'].mean():7.1f}  "
            f"size={grp['packet_size'].mean():7.1f}  "
            f"ports={grp['unique_dst_ports'].mean():7.1f}  "
            f"entropy={grp['entropy'].mean():6.3f}"
        )
    print("=" * 64)
    return df


def train_isolation_forest(df: pd.DataFrame, contamination: float, seed: int) -> IsolationForest:
    X = df[["packet_count", "packet_size", "unique_dst_ports", "entropy"]].to_numpy(dtype=np.float64)

    print(f"\nTraining IsolationForest  shape={X.shape}")
    print(f"  Configured Contamination Factor: {contamination}")

    model = IsolationForest(
        n_estimators=250, # Boosted trees for smoother decision vectors
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X)

    preds = model.predict(X)
    n_outliers = int((preds == -1).sum())
    print(f"  In-sample outliers classified: {n_outliers}/{len(preds)} ({100 * n_outliers / len(preds):.1f}%)")
    return model


def main() -> int:
    p = argparse.ArgumentParser(description="Train CyberShield IsolationForest baseline model.")
    p.add_argument("--out", default="model.joblib", help="Output model path (.joblib).")
    p.add_argument("--n", type=int, default=8000, help="Number of synthetic flow samples.")
    # FIXED: Default contamination shifted from 0.20 down to 0.02 so the model is not hyper-sensitive
    p.add_argument("--contamination", type=float, default=0.02, help="Expected anomaly fraction.")
    p.add_argument("--seed", type=int, default=42, help="Random seed.")
    p.add_argument("--dump-csv", default="", help="Optional: write the synthetic dataset to this CSV path.")
    args = p.parse_args()

    print("\n[1/3] Compiling tailored network profile shapes ...")
    df = generate_synthetic_normal(n=args.n, seed=args.seed)

    print("\n[2/3] Constructing Isolation Forest boundaries ...")
    model = train_isolation_forest(df, contamination=args.contamination, seed=args.seed)

    print("\n[3/3] Exporting trained model cluster ...")
    out_path = Path(args.out)
    joblib.dump(model, out_path)

    print(f"\n🚀 Production Model deployed successfully → {out_path.resolve()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())