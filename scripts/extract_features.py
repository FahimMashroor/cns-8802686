#!/usr/bin/env python3
"""
Reads  : project/data/experiment/capture_files/*.pcap
Writes : project/data/experiment/trace_csv/experiment/all_traces.csv
         project/data/experiment/trace_csv/<label>.csv
"""

import os
import csv
import sys
import numpy as np
from pathlib import Path
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP

# ── Path setup (works from any working directory) ─────────
SCRIPT_DIR   = Path(__file__).resolve().parent        # project/scripts/
PROJECT_ROOT = SCRIPT_DIR.parent                       # project/
CAPTURE_DIR  = PROJECT_ROOT / "data" / "experiment" / "capture_files"
OUTPUT_DIR   = PROJECT_ROOT / "data" / "experiment" / "trace_csv"
# ─────────────────────────────────────────────────────────


def get_local_ip(packets) -> str | None:
    """
    Heuristic: the most frequent source IP in the capture
    is assumed to be the local machine.
    """
    ips = [pkt[IP].src for pkt in packets if IP in pkt]
    if not ips:
        return None
    return Counter(ips).most_common(1)[0][0]


def build_packet_sequence(packets, local_ip: str) -> tuple[list[int], list[float]]:
    """
    Returns:
        signed_sizes  — positive = outgoing, negative = incoming
        rel_times     — timestamps relative to first packet (seconds)
    """
    signed_sizes = []
    rel_times    = []
    base_time    = None

    for pkt in packets:
        if IP not in pkt:
            continue
        if TCP not in pkt and UDP not in pkt:
            continue

        t = float(pkt.time)
        if base_time is None:
            base_time = t

        direction    = +1 if pkt[IP].src == local_ip else -1
        signed_sizes.append(direction * len(pkt))
        rel_times.append(round(t - base_time, 6))

    return signed_sizes, rel_times


def burst_features(signed_sizes: list[int]) -> tuple[int, float, int]:
    """
    A burst = a consecutive run of packets in the same direction.
    Returns: (burst_count, burst_avg_size, burst_max_size)
    """
    if not signed_sizes:
        return 0, 0.0, 0

    bursts        = []
    current_dir   = None
    current_count = 0

    for s in signed_sizes:
        d = 1 if s > 0 else -1
        if d == current_dir:
            current_count += 1
        else:
            if current_dir is not None:
                bursts.append(current_count)
            current_dir   = d
            current_count = 1
    bursts.append(current_count)   # flush last burst

    return (
        len(bursts),
        round(float(np.mean(bursts)), 4),
        int(max(bursts)),
    )


def timing_features(rel_times: list[float]) -> dict:
    """
    Inter-packet timing statistics.
    """
    ipt = np.diff(rel_times) if len(rel_times) > 1 else np.array([0.0])
    return {
        "ipt_mean": round(float(np.mean(ipt)),          6),
        "ipt_std":  round(float(np.std(ipt)),           6),
        "ipt_p25":  round(float(np.percentile(ipt, 25)),6),
        "ipt_p50":  round(float(np.percentile(ipt, 50)),6),
        "ipt_p75":  round(float(np.percentile(ipt, 75)),6),
        "ipt_max":  round(float(np.max(ipt)),           6),
    }


def extract_features(pcap_path: Path) -> dict | None:
    """
    Full feature extraction pipeline for one .pcap trace.

    Feature groups
    ──────────────
    1. Metadata          — filename, label, capture duration
    2. Aggregate stats   — packet/byte counts, directional ratios
    3. Packet size stats — mean, std, min, max of |sizes|
    4. Inter-packet timing (IPT) — mean, std, percentiles, max
    5. Burst features    — count, avg size, max size
    6. Raw sequences     — signed sizes + timestamps (for deep learning)
    """
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"    [!] Failed to read {pcap_path.name}: {e}")
        return None

    if not packets:
        return None

    local_ip = get_local_ip(packets)
    if local_ip is None:
        return None

    signed_sizes, rel_times = build_packet_sequence(packets, local_ip)

    if not signed_sizes:
        return None

    sizes_arr = np.array(signed_sizes)
    outgoing  = sizes_arr[sizes_arr > 0]
    incoming  = sizes_arr[sizes_arr < 0]
    abs_sizes = np.abs(sizes_arr)

    # ── Aggregate ──────────────────────────────────────────
    out_pkts  = len(outgoing)
    in_pkts   = len(incoming)
    out_bytes = int(np.sum(outgoing))
    in_bytes  = int(np.sum(np.abs(incoming)))

    # ── Bursts ─────────────────────────────────────────────
    burst_cnt, burst_avg, burst_max = burst_features(signed_sizes)

    # ── Assemble ───────────────────────────────────────────
    label = pcap_path.stem.split("_trace")[0]

    features = {
        # ── Metadata ──────────────────────────────────────
        "file":               pcap_path.name,
        "label":              label,
        "duration_sec":       round(rel_times[-1] - rel_times[0], 6) if rel_times else 0,

        # ── Aggregate stats ────────────────────────────────
        "total_packets":      len(sizes_arr),
        "out_packets":        out_pkts,
        "in_packets":         in_pkts,
        "total_bytes":        int(np.sum(abs_sizes)),
        "out_bytes":          out_bytes,
        "in_bytes":           in_bytes,
        "in_out_pkt_ratio":   round(in_pkts  / out_pkts,  4) if out_pkts  > 0 else 0,
        "in_out_byte_ratio":  round(in_bytes / out_bytes, 4) if out_bytes > 0 else 0,

        # ── Packet size stats ──────────────────────────────
        "pkt_size_mean":      round(float(np.mean(abs_sizes)), 4),
        "pkt_size_std":       round(float(np.std(abs_sizes)),  4),
        "pkt_size_min":       int(np.min(abs_sizes)),
        "pkt_size_max":       int(np.max(abs_sizes)),

        # ── Inter-packet timing ────────────────────────────
        **timing_features(rel_times),

        # ── Burst features ─────────────────────────────────
        "burst_count":        burst_cnt,
        "burst_avg_size":     burst_avg,
        "burst_max_size":     burst_max,

        # ── Raw sequences (space-separated for ML pipelines)
        "packet_sizes_seq":   " ".join(map(str, signed_sizes)),
        "timestamps_seq":     " ".join(map(str, rel_times)),
    }

    return features


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def process_all():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    pcap_files = sorted(CAPTURE_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"[!] No .pcap files found in: {CAPTURE_DIR}")
        sys.exit(1)

    print("============================================")
    print("  Website Fingerprinting — Feature Extract")
    print("============================================")
    print(f"  Source : {CAPTURE_DIR}")
    print(f"  Output : {OUTPUT_DIR}")
    print(f"  Files  : {len(pcap_files)} .pcap traces")
    print("============================================\n")

    skipped   = 0
    processed = 0

    for pcap_path in pcap_files:
        print(f"[*] {pcap_path.name}")
        feats = extract_features(pcap_path)

        if feats is None:
            print("    [!] Skipped — no usable packets\n")
            skipped += 1
            continue

        print(f"    label={feats['label']:<15} "
              f"pkts={feats['total_packets']:<6} "
              f"dur={feats['duration_sec']}s")

        # ── Write individual CSV (same stem as .pcap) ──────
        individual_path = OUTPUT_DIR / f"{pcap_path.stem}.csv"
        write_csv(individual_path, [feats], list(feats.keys()))
        print(f"    → {individual_path.relative_to(PROJECT_ROOT)}\n")

        processed += 1

    print(f"[✓] Done — processed: {processed}  skipped: {skipped}")
    print("\n[✓] Feature extraction complete.")

if __name__ == "__main__":
    process_all()