#!/usr/bin/env python3
import socket
import sys
import ctypes
import time
import json
from audit_contract import (
    SovereignAuditFrame, SovereignResponseFrame,
    SOVR_MAGIC, SOVR_VERSION, ROLE_FIDUCIARY_PR,
    SOVR_STATUS_SUCCESS
)
from sovereign_pseudonyms import SOVR_ROOT_PUBKEYS

HOST = "127.0.0.1"
PORT = 9998

def send_frame(sock, frame):
    sock.sendall(bytes(frame))
    resp_raw = b""
    while len(resp_raw) < ctypes.sizeof(SovereignResponseFrame):
        chunk = sock.recv(ctypes.sizeof(SovereignResponseFrame) - len(resp_raw))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        resp_raw += chunk
    return SovereignResponseFrame.from_buffer_copy(resp_raw)

def build_benchmark_frame(seq_id, node_count):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = SOVR_VERSION
    frame.fiduciary_role = ROLE_FIDUCIARY_PR
    frame.sequence_id = seq_id
    frame.veteran_verified = 1
    frame.statutory_duty = 1
    frame.corporate_defense_valid = 0
    frame.can_be_administered_away = 0
    frame.node_count = node_count
    frame.claimant = b"Christopher Carroll"
    frame.dockets[0].value = b"4FA-23-01878PR-AK-SUPERIOR"[:31]

    for n in range(node_count):
        frame.nodes[n].name = f"Node-{n}".encode()[:31]
        frame.nodes[n].era_year = 1800 + n * 10
        frame.nodes[n].territorial_hub = b"Yukon Drain"[:23]
        frame.nodes[n].title_type = 1

    frame.quorum_count = 3
    frame.signer_bitmap = 0x07
    for w_i in range(3):
        k = SOVR_ROOT_PUBKEYS[w_i]
        for b_i in range(32):
            frame.witnesses[w_i].signer_pubkey[b_i] = k[b_i]

    return frame

def main():
    print(f"[*] Connecting to seL4 COM2 ({HOST}:{PORT})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    results = {}
    seq_counter = int(time.time())
    iterations = 50

    print("[*] Executing sweep: node_count 1 -> 8 (50 iterations each)...")
    print(f"{'Nodes':<6} | {'Throughput (fps)':<18} | {'Median (ms)':<12} | {'P95 (ms)':<10} | {'Max (ms)':<10}")
    print("-" * 65)

    for n_count in range(1, 9):
        latencies = []
        t_start = time.time()
        for _ in range(iterations):
            seq_counter += 1
            f = build_benchmark_frame(seq_counter, n_count)
            t0 = time.time()
            resp = send_frame(sock, f)
            t1 = time.time()
            assert resp.status_code == SOVR_STATUS_SUCCESS
            latencies.append((t1 - t0) * 1000.0)

        t_end = time.time()
        total_time = t_end - t_start
        fps = iterations / total_time
        latencies.sort()
        med = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)]
        max_lat = latencies[-1]

        results[str(n_count)] = {
            "throughput_fps": round(fps, 2),
            "median_ms": round(med, 2),
            "p95_ms": round(p95, 2),
            "max_ms": round(max_lat, 2)
        }
        print(f"{n_count:<6} | {fps:<18.2f} | {med:<12.2f} | {p95:<10.2f} | {max_lat:<10.2f}")

    sock.close()
    out_path = "/data/data/com.termux/files/home/Telephone_port/scaling_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Saturated scaling results written to: {out_path}")

if __name__ == "__main__":
    main()
