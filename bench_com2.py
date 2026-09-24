#!/usr/bin/env python3
import time
import socket
import ctypes
import statistics
from audit_contract import (
    serialize_estate_to_frame,
    compute_frame_binary_hash,
    SovereignResponseFrame,
    SOVA_MAGIC,
    SOVR_STATUS_SUCCESS
)

HOST = "127.0.0.1"
PORT = 9998
FRAME_COUNT = 100

def run_benchmark(iterations=FRAME_COUNT):
    frame = serialize_estate_to_frame()
    payload = bytes(frame)
    expected_hash = compute_frame_binary_hash(frame)
    resp_len = ctypes.sizeof(SovereignResponseFrame)

    latencies_ms = []
    print(f"[*] Connecting to seL4 COM2 at {HOST}:{PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    sock.connect((HOST, PORT))

    print(f"[*] Streaming {iterations} consecutive audit frames (808 B each)...")
    wall_start = time.perf_counter()

    for i in range(iterations):
        t0 = time.perf_counter()
        sock.sendall(payload)

        resp_buf = bytearray()
        while len(resp_buf) < resp_len:
            chunk = sock.recv(resp_len - len(resp_buf))
            if not chunk:
                raise ConnectionResetError(f"Connection dropped on iteration {i}")
            resp_buf.extend(chunk)

        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

        resp = SovereignResponseFrame.from_buffer_copy(resp_buf)
        assert resp.magic == SOVA_MAGIC, f"Bad magic on iter {i}: {hex(resp.magic)}"
        assert resp.status_code == SOVR_STATUS_SUCCESS, f"Rejection on iter {i}: {hex(resp.status_code)}"
        assert bytes(resp.root_hash).hex() == expected_hash, f"Hash mismatch on iter {i}"

    wall_duration = time.perf_counter() - wall_start
    sock.close()

    throughput_fps = iterations / wall_duration
    bandwidth_kbps = (iterations * (len(payload) + resp_len) * 8) / (wall_duration * 1000.0)

    print("\n=== BENCHMARK RESULTS ===")
    print(f"  Frames Processed : {iterations}")
    print(f"  Total Duration   : {wall_duration:.3f} s")
    print(f"  Throughput       : {throughput_fps:.1f} frames/sec")
    print(f"  Effective Data   : {bandwidth_kbps:.2f} kbps")
    print(f"  Latency Min      : {min(latencies_ms):.2f} ms")
    print(f"  Latency Median   : {statistics.median(latencies_ms):.2f} ms")
    print(f"  Latency P95      : {statistics.quantiles(latencies_ms, n=20)[18]:.2f} ms")
    print(f"  Latency Max      : {max(latencies_ms):.2f} ms")

if __name__ == "__main__":
    run_benchmark()
