#! /usr/bin/env python3
"""
ids-online-save-csv.py
Sniffs packets, computes window features every interval, and APPENDS rows to a CSV file.
- Creates a NEW CSV per run (timestamped) unless --out points to a specific file.
- No prediction/model loading; only feature extraction + labeling by port==9.
- Uses a thread-safe deque buffer and flushes to disk every interval.
"""

import argparse
import os
import sys
import time
import signal
import threading
from threading import Lock, Event
from collections import deque
from datetime import datetime
from pathlib import Path

import pandas as pd
from scipy.stats import entropy
from scapy.all import IP, TCP, UDP, sniff


# ---------------------- Globals & Defaults ----------------------

pkt_buffer = deque()
buf_lock = Lock()
stop_event = Event()

DEFAULT_INTERVAL = 1.0            # seconds
DEFAULT_ABN_SIZE = 1500           # bytes
DEFAULT_PORT_FREQ_THRESH = 5
DEFAULT_SHORT_LIVED_THRESH = 5


# ---------------------- Packet Handler --------------------------

def receive_pkt(pkt):
    """Collect minimal per-packet attributes into a buffer (thread-safe)."""
    if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        return

    if not pkt.haslayer(IP):
        return

    ts = pkt.time
    ip = pkt[IP]

    # Defaults
    ack = syn = fin = psh = urg = rst = 0
    sport = dport = seq = acknum = 0
    tcp_flag = udp_flag = 0
    payload_size = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        ack = int(tcp.flags.A)
        syn = int(tcp.flags.S)
        fin = int(tcp.flags.F)
        psh = int(tcp.flags.P)
        urg = int(tcp.flags.U)
        rst = int(tcp.flags.R)
        sport = tcp.sport
        dport = tcp.dport
        seq = tcp.seq
        acknum = tcp.ack
        tcp_flag = 1
        payload_size = len(tcp.payload)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        sport = udp.sport
        dport = udp.dport
        udp_flag = 1
        payload_size = len(udp.payload)

    # Label: 1 if either port is 9, else 0
    label = 1 if (sport == 9 or dport == 9) else 0

    pkt_dict = {
        'Timestamp': ts,
        'Source': ip.src,
        'Destination': ip.dst,
        'Protocol': ip.proto,
        'SrcPort': sport,
        'DstPort': dport,
        'TCP': tcp_flag,
        'UDP': udp_flag,
        'TTL': ip.ttl,
        'ACK': ack,
        'SYN': syn,
        'FIN': fin,
        'PSH': psh,
        'URG': urg,
        'RST': rst,
        'SequenceNumber': seq,
        'AcknowledgmentNumber': acknum,
        'PacketSize': len(pkt),
        'PayloadSize': payload_size,
        'Label': label,
    }

    with buf_lock:
        pkt_buffer.append(pkt_dict)


# ---------------------- Feature Functions -----------------------

def _entropy_of_series(vals: pd.Series) -> float:
    if vals.empty:
        return 0.0
    counts = vals.value_counts()
    probs = counts / counts.sum()
    return float(entropy(probs)) if probs.size > 0 else 0.0


def calculate_destination_port_entropy(group: pd.DataFrame) -> float:
    return _entropy_of_series(group['DstPort'])


def most_frequent_src_port(group: pd.DataFrame, threshold: int) -> int:
    vc = group['SrcPort'].value_counts()
    return int(vc.idxmax()) if (not vc.empty and vc.max() > threshold) else 0


def most_frequent_dst_port(group: pd.DataFrame, threshold: int) -> int:
    vc = group['DstPort'].value_counts()
    return int(vc.idxmax()) if (not vc.empty and vc.max() > threshold) else 0


def calculate_short_lived_connections(group: pd.DataFrame, short_lived_threshold: int) -> int:
    flows = group.groupby(['Source', 'Destination', 'SrcPort', 'DstPort', 'Protocol']).size()
    return int((flows < short_lived_threshold).sum())


def repeated_connection_attempts(group: pd.DataFrame) -> int:
    return int(group['Destination'].duplicated().sum())


def network_scanning_activity(group: pd.DataFrame) -> int:
    # naive: SYN=1 and ACK=0 as "scan-ish"
    return int(((group['SYN'] == 1) & (group['ACK'] == 0)).sum())


def calculate_flow_rate(group: pd.DataFrame) -> float:
    # packets per second across the window duration inferred from timestamps
    total_time = group['TimeDiff'].sum()
    n = len(group)
    return float(n / total_time) if total_time > 0 else float(n)


def calculate_source_entropy(group: pd.DataFrame) -> float:
    return _entropy_of_series(group['Source'])


def connection_errors(group: pd.DataFrame) -> int:
    return int((group['RST'] == 1).sum())


def most_frequent_packet_size_freq(group: pd.DataFrame) -> int:
    vc = group['PacketSize'].value_counts()
    return int(vc.max()) if not vc.empty else 0


def abnormal_size_freq(group: pd.DataFrame, threshold: int) -> int:
    return int((group['PacketSize'] > threshold).sum())


def sequence_number_variance(group: pd.DataFrame) -> float:
    return float(group['SequenceNumber'].var(ddof=0))  # ddof=0 for population variance


def calculate_avg_packet_number(group: pd.DataFrame, interval: float) -> float:
    return float(len(group) / max(interval, 1e-9))


def calculate_flag_frequency(group: pd.DataFrame, flag: str, interval: float) -> float:
    count = int((group[flag] == 1).sum())
    return float(count / max(interval, 1e-9))


def calculate_tcp_frequency(group: pd.DataFrame) -> float:
    total = len(group)
    return float((group['TCP'] == 1).sum() / total) if total else 0.0


def calculate_udp_frequency(group: pd.DataFrame) -> float:
    total = len(group)
    return float((group['UDP'] == 1).sum() / total) if total else 0.0


def most_frequent_protocol(group: pd.DataFrame) -> int:
    if group.empty:
        return 0
    return int(group['Protocol'].value_counts().idxmax())


def packet_size_variability(group: pd.DataFrame) -> float:
    return float(group['PacketSize'].var(ddof=0))


def most_frequent_payload_size(group: pd.DataFrame) -> int:
    vc = group['PayloadSize'].value_counts()
    return int(vc.idxmax()) if not vc.empty else 0


def average_payload_size(group: pd.DataFrame) -> float:
    return float(group['PayloadSize'].mean()) if not group.empty else 0.0


# ---------------------- Processing Loop -------------------------

def process_data_periodically(out_path: Path,
                              interval: float,
                              abnormal_size_threshold: int,
                              port_frequency_threshold: int,
                              short_lived_threshold: int):
    """Every `interval` seconds, drain buffer, compute features, and append to CSV."""
    header_written = out_path.exists() and out_path.stat().st_size > 0

    while not stop_event.is_set():
        time.sleep(interval)

        with buf_lock:
            if not pkt_buffer:
                continue
            batch = list(pkt_buffer)
            pkt_buffer.clear()

        df = pd.DataFrame(batch)
        # Ensure Timestamp is datetime and sort
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')
        df = df.sort_values(by='Timestamp')
        df['TimeDiff'] = df['Timestamp'].diff().dt.total_seconds().fillna(0.0)

        # Single group (window)
        df['key'] = 1
        grouped = df.groupby('key')

        # Compute window features (each returns a scalar)
        feats = pd.DataFrame({'key': [1]})

        feats['DstPortEntropy'] = grouped.apply(calculate_destination_port_entropy).values
        feats['PacketCount'] = grouped.size().values
        feats['MostFreqSrcPort'] = grouped.apply(lambda g: most_frequent_src_port(g, port_frequency_threshold)).values
        feats['MostFreqDstPort'] = grouped.apply(lambda g: most_frequent_dst_port(g, port_frequency_threshold)).values
        feats['PacketSizeStd'] = grouped['PacketSize'].std(ddof=0).values
        feats['AvgPacketSize'] = grouped['PacketSize'].mean().values
        feats['MostFreqPacketSizeFreq'] = grouped.apply(most_frequent_packet_size_freq).values
        feats['AbnormalSizeFreq'] = grouped.apply(lambda g: abnormal_size_freq(g, abnormal_size_threshold)).values
        feats['SeqNumVariance'] = grouped.apply(sequence_number_variance).values
        feats['ShortLivedConnections'] = grouped.apply(lambda g: calculate_short_lived_connections(g, short_lived_threshold)).values
        feats['RepeatedAttempts'] = grouped.apply(repeated_connection_attempts).values
        feats['ScanningActivity'] = grouped.apply(network_scanning_activity).values
        feats['FlowRate'] = grouped.apply(calculate_flow_rate).values
        feats['SourceEntropy'] = grouped.apply(calculate_source_entropy).values
        feats['ConnectionErrors'] = grouped.apply(connection_errors).values
        feats['AvgPacketNumber'] = grouped.apply(lambda g: calculate_avg_packet_number(g, interval)).values
        feats['SYNFrequency'] = grouped.apply(lambda g: calculate_flag_frequency(g, 'SYN', interval)).values
        feats['ACKFrequency'] = grouped.apply(lambda g: calculate_flag_frequency(g, 'ACK', interval)).values
        feats['TCPFrequency'] = grouped.apply(calculate_tcp_frequency).values
        feats['UDPFrequency'] = grouped.apply(calculate_udp_frequency).values
        feats['MostFreqProtocol'] = grouped.apply(most_frequent_protocol).values
        feats['PacketSizeVar'] = grouped.apply(packet_size_variability).values
        feats['MostFreqPayloadSize'] = grouped.apply(most_frequent_payload_size).values
        feats['AvgPayloadSize'] = grouped.apply(average_payload_size).values

        # Cross-join to attach window features to each packet row, then drop identifiers
        merged = df.merge(feats, on='key', how='left').drop(columns=[
            'key', 'Timestamp', 'TimeDiff', 'Source', 'Destination', 'SrcPort', 'DstPort'
        ])

        # Fill and append to CSV
        merged = merged.fillna(0)

        # Append safely: write to a temp then rename to reduce partial-write risk
        tmp_path = out_path.with_suffix(out_path.suffix + '.part')
        # If file already exists, we want to append. Pandas cannot "append" to an existing tmp then rename, so:
        # Simple, robust approach: append directly and rely on atomic close.
        # Then, to ensure durability, we re-open and fsync.
        merged.to_csv(out_path, mode='a', header=not header_written, index=False)
        header_written = True

        # fsync to be extra safe
        with open(out_path, 'ab', buffering=0) as fh:
            fh.flush()
            os.fsync(fh.fileno())

        print(f"[{datetime.now().strftime('%H:%M:%S')}] wrote {len(merged)} rows -> {out_path}")


# ---------------------- Sniffer Thread --------------------------

def packet_sniffer(interface: str, bpf_filter: str | None):
    # Loop with short timeouts so we can honor stop_event
    while not stop_event.is_set():
        try:
            sniff(iface=interface, prn=receive_pkt, store=0, filter=bpf_filter or "", timeout=1)
        except Exception as e:
            # Keep going; transient libpcap/scapy errors shouldn't kill the program
            print(f"[sniffer] error: {e}", file=sys.stderr)
            time.sleep(0.5)


# ---------------------- CLI & Main -------------------------------

def _build_output_path(out: str | None) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    default_name = f"features-{ts}.csv"
    if out is None:
        return Path(default_name).resolve()
    p = Path(out).expanduser().resolve()
    if p.is_dir():
        p.mkdir(parents=True, exist_ok=True)
        return (p / default_name).resolve()
    # ensure parent exists
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def main():
    ap = argparse.ArgumentParser(description="Online IDS feature extractor (CSV appender)")
    ap.add_argument("--iface", default="eth0", help="Network interface to sniff (default: eth0)")
    ap.add_argument("--filter", default="ip and (tcp or udp)", help="BPF filter to apply")
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Processing interval in seconds")
    ap.add_argument("--abnormal-size", type=int, default=DEFAULT_ABN_SIZE, help="Packet size threshold for 'abnormal'")
    ap.add_argument("--port-freq-threshold", type=int, default=DEFAULT_PORT_FREQ_THRESH,
                    help="Min occurrences to consider a port as 'most frequent'")
    ap.add_argument("--short-lived-threshold", type=int, default=DEFAULT_SHORT_LIVED_THRESH,
                    help="Packets per flow below which a connection is 'short-lived'")
    ap.add_argument("--out", default=None,
                    help="Output CSV path OR directory. If directory, a new timestamped file is created inside. "
                         "If omitted, a timestamped file is created in the current directory.")

    args = ap.parse_args()

    out_path = _build_output_path(args.out)
    print(f"Writing features to: {out_path}")

    # Signal handling for clean shutdown
    def _sig_handler(sig, frame):
        print("Stopping...")
        stop_event.set()
    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    # Start threads
    sniffer_t = threading.Thread(target=packet_sniffer, args=(args.iface, args.filter), daemon=True)
    sniffer_t.start()

    processor_t = threading.Thread(
        target=process_data_periodically,
        args=(out_path, args.interval, args.abnormal_size, args.port_freq_threshold, args.short_lived_threshold),
        daemon=True,
    )
    processor_t.start()

    # Keep main alive
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        stop_event.set()
        sniffer_t.join(timeout=2)
        processor_t.join(timeout=2)
        print("Exited cleanly.")

if __name__ == "__main__":
    main()
