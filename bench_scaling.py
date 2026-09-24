#!/usr/bin/env python3
import socket
import time
import ctypes
import statistics
import sys
import json

from audit_contract import (
    SovereignAuditFrame,
    SovereignResponseFrame,
    SOVA_MAGIC,
    SOVR_STATUS_SUCCESS
)

SOVR_MAGIC = 0x534F5652
TITLE_ABORIGINAL_SOVEREIGN = 0x0001
COM2_HOST = "127.0.0.1"
COM2_PORT = 9998

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf.extend(chunk)
    return bytes(buf)

def build_frame(node_count):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = 1
    frame.fiduciary_role = 0xC001
    frame.veteran_verified = 1
    frame.node_count = node_count
    frame.claimant = b"Node Scaling Benchmark Suite"
    frame.dockets[0].value = b"4FA-23-01878PR-IN-THE-SUPERIOR-COURT-OF-ALASKA"
    frame.dockets[1].value = b"3AN-24-00123CI"

    for i in range(node_count):
        node = frame.nodes[i]
        node.title_type = TITLE_ABORIGINAL_SOVEREIGN
        node.name = f"Node-{i}".encode("utf-8")
        node.era_year = 1900 + i
        node.territorial_hub = b"Fairbanks/Tanana"
    return bytes(frame)

def run_sweep(iterations_per_node=50):
    print(f"[*] Connecting to seL4 COM2 ({COM2_HOST}:{COM2_PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((COM2_HOST, COM2_PORT))

    results = []
    resp_size = ctypes.sizeof(SovereignResponseFrame)

    print(f"[*] Executing sweep: node_count 1 -> 8 ({iterations_per_node} iterations each)...")
    print(f"{'Nodes':<6} | {'Throughput (fps)':<18} | {'Median (ms)':<12} | {'P95 (ms)':<10} | {'Max (ms)':<10}")
    print("-" * 65)

    try:
        for nc in range(1, 9):
            frame_bytes = build_frame(nc)
            latencies = []
            start_total = time.perf_counter()

            for _ in range(iterations_per_node):
                t0 = time.perf_counter()
                s.sendall(frame_bytes)
                raw_resp = recv_exact(s, resp_size)
                t1 = time.perf_counter()

                resp = SovereignResponseFrame.from_buffer_copy(raw_resp)
                assert resp.magic == SOVA_MAGIC
                assert resp.status_code == SOVR_STATUS_SUCCESS

                latencies.append((t1 - t0) * 1000.0)

            total_sec = time.perf_counter() - start_total
            throughput = iterations_per_node / total_sec
            median_lat = statistics.median(latencies)
            p95_lat = sorted(latencies)[int(len(latencies) * 0.95)]
            max_lat = max(latencies)

            results.append({
                "nodes": nc,
                "throughput_fps": round(throughput, 2),
                "latency_median_ms": round(median_lat, 2),
                "latency_p95_ms": round(p95_lat, 2),
                "latency_max_ms": round(max_lat, 2)
            })

            print(f"{nc:<6} | {throughput:<18.2f} | {median_lat:<12.2f} | {p95_lat:<10.2f} | {max_lat:<10.2f}")

        with open("/data/data/com.termux/files/home/Tordial-GS/scaling_results.json", "w") as fp:
            json.dump(results, fp, indent=2)
        print("\n[+] Scaling benchmark complete. Saved to ~/Tordial-GS/scaling_results.json")
    finally:
        s.close()

if __name__ == "__main__":
    run_sweep(iterations_per_node=50)
