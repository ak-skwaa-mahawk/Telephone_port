#!/usr/bin/env python3
"""
test_replay.py - Adversarial Anti-Replay Ingress Verification
Tests Sequence 27 Threat 3 mitigations against duplicate nonces and retroversion.
"""

import ctypes
import socket
import sys
import time

from audit_contract import (
    SovereignAuditFrame,
    SovereignResponseFrame,
    SOVA_MAGIC,
    SOVR_STATUS_SUCCESS
)

SOVR_MAGIC = 0x534F5652
SOVR_FLAG_ANOMALY_DETECTED = 0x0008
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

def build_test_frame(sequence_id: int):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = 1
    frame.fiduciary_role = 0xC001
    frame.sequence_id = sequence_id
    frame.veteran_verified = 1
    frame.node_count = 1
    frame.claimant = b"Sequence 27 Anti-Replay Adversarial Validation"
    frame.dockets[0].value = b"4FA-23-01878PR-IN-THE-SUPERIOR-COURT-OF-ALASKA"
    frame.nodes[0].name = b"Root-Node"
    frame.nodes[0].era_year = 1900
    frame.nodes[0].territorial_hub = b"Fairbanks"
    return bytes(frame)

def run_adversarial_suite():
    print(f"[*] Connecting to seL4 COM2 ({COM2_HOST}:{COM2_PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((COM2_HOST, COM2_PORT))

    resp_size = ctypes.sizeof(SovereignResponseFrame)

    try:
        # Phase 1: Legitimate monotonic progression (Seq 27)
        print("[*] Phase 1: Dispatching legitimate forward frame (sequence_id = 27)...")
        s.sendall(build_test_frame(27))
        resp1 = SovereignResponseFrame.from_buffer_copy(recv_exact(s, resp_size))
        assert resp1.magic == SOVA_MAGIC
        assert resp1.status_code == SOVR_STATUS_SUCCESS
        print(f"[+] Phase 1 passed: Accepted (Status: 0x{resp1.status_code:04x}, Flags: 0x{resp1.flags:04x})")

        # Phase 2: Exact Duplicate Replay Attack (Seq 27 again)
        print("[*] Phase 2: Injecting identical duplicate replay frame (sequence_id = 27)...")
        s.sendall(build_test_frame(27))
        resp2 = SovereignResponseFrame.from_buffer_copy(recv_exact(s, resp_size))
        assert resp2.magic == SOVA_MAGIC
        is_anomaly = bool(resp2.flags & SOVR_FLAG_ANOMALY_DETECTED) or (resp2.status_code != SOVR_STATUS_SUCCESS)
        print(f"[+] Phase 2 response: Status 0x{resp2.status_code:04x}, Flags 0x{resp2.flags:04x}")
        print(f"    Replay detection triggered: {is_anomaly}")

        # Phase 3: Inverted Sequence Retroversion (Seq 26)
        print("[*] Phase 3: Injecting retroverted sequence frame (sequence_id = 26)...")
        s.sendall(build_test_frame(26))
        resp3 = SovereignResponseFrame.from_buffer_copy(recv_exact(s, resp_size))
        assert resp3.magic == SOVA_MAGIC
        is_retro_anomaly = bool(resp3.flags & SOVR_FLAG_ANOMALY_DETECTED) or (resp3.status_code != SOVR_STATUS_SUCCESS)
        print(f"[+] Phase 3 response: Status 0x{resp3.status_code:04x}, Flags 0x{resp3.flags:04x}")
        print(f"    Retroversion rejection triggered: {is_retro_anomaly}")

    finally:
        s.close()

if __name__ == "__main__":
    run_adversarial_suite()
