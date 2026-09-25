#!/usr/bin/env python3
"""
bench_scaling.py - Sovereign Evaluation Appliance Multi-Node Scaling Sweep
Sweeps lineage graph node counts n = 1 .. 8 across 50 iterations each
under saturated Q16.16 arithmetic boundary matrices.
"""

import ctypes
import json
import os
import socket
import statistics
import time

from audit_contract import (
    SovereignAuditFrame,
    SovereignResponseFrame,
    SOVA_MAGIC,
    SOVR_STATUS_SUCCESS
)

SOVR_MAGIC = 0x534F5652
COM2_HOST = "127.0.0.1"
COM2_PORT = 9998
RESULTS_FILE = os.path.expanduser("~/Telephone_port/scaling_results.json")

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf.extend(chunk)
    return bytes(buf)

def build_frame(node_count: int, seq_id: int) -> bytes:
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = 1
    frame.fiduciary_role = 0xC001
    frame.sequence_id = seq_id
    frame.veteran_verified = 1
    frame.node_count = node_count
    frame.quorum_count = 3
    frame.signer_bitmap = 0x07
    frame.claimant = f"Saturated Q16 Scaling Sweep Node-{node_count}".encode("utf-8")
    frame.dockets[0].value = b"4FA-23-01878PR-AK-SUPERIOR"

    for n in range(node_count):
        frame.nodes[n].name = f"Node-{n}".encode("utf-8")
        frame.nodes[n].era_year = 1900 + (n * 10)
        frame.nodes[n].territorial_hub = b"Fairbanks-AK"
        # Saturating Q16.16 feature bounds
        frame.nodes[n].title_type = 0x7FFFFFFF if (n % 2 == 0) else 0x80000000

    return bytes(frame)

def run_sweep(iterations_per_node=50):
    print(f"[*] Connecting to seL4 COM2 ({COM2_HOST}:{COM2_PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((COM2_HOST, COM2_PORT))

    resp_size = ctypes.sizeof(SovereignResponseFrame)
    sweep_results = {}
    global_seq = 20000

    print(f"[*] Executing sweep: node_count 1 -> 8 ({iterations_per_node} iterations each)...")
    print(f"{'Nodes':<6} | {'Throughput (fps)':<18} | {'Median (ms)':<12} | {'P95 (ms)':<10} | {'Max (ms)':<10}")
    print("-" * 65)

    try:
        for node_count in range(1, 9):
            latencies = []
            start_total = time.time()

            for i in range(iterations_per_node):
                global_seq += 1
                payload = build_frame(node_count, global_seq)

                t0 = time.time()
                s.sendall(payload)
                raw_resp = recv_exact(s, resp_size)
                t1 = time.time()

                resp = SovereignResponseFrame.from_buffer_copy(raw_resp)
                if resp.status_code != SOVR_STATUS_SUCCESS:
                    raise RuntimeError(f"Node {node_count} Iter {i}: status=0x{resp.status_code:04x}, flags=0x{resp.flags:04x}")

                latencies.append((t1 - t0) * 1000.0)

            total_elapsed = time.time() - start_total
            fps = iterations_per_node / total_elapsed
            latencies.sort()
            med = statistics.median(latencies)
            p95 = latencies[int(len(latencies) * 0.95)]
            max_lat = max(latencies)

            sweep_results[node_count] = {
                "throughput_fps": round(fps, 2),
                "median_ms": round(med, 2),
                "p95_ms": round(p95, 2),
                "max_ms": round(max_lat, 2)
            }

            print(f"{node_count:<6} | {fps:<18.2f} | {med:<12.2f} | {p95:<10.2f} | {max_lat:<10.2f}")

    finally:
        s.close()

    with open(RESULTS_FILE, "w") as f:
        json.dump(sweep_results, f, indent=2)
    print(f"[+] Saturated scaling results written to: {RESULTS_FILE}")

if __name__ == "__main__":
    run_sweep(iterations_per_node=50)
