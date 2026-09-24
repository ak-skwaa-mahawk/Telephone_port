#!/usr/bin/env python3
import socket
import time
import ctypes
import sys

from audit_contract import (
    SovereignAuditFrame,
    SovereignResponseFrame,
    SOVR_MAGIC,
    SOVA_MAGIC,
    SOVR_FLAG_STATUTORY_DUTY,
    SOVR_STATUS_SUCCESS
)

SOVR_FLAG_ANOMALY_DETECTED = (1 << 3)  # 0x0008

COM2_HOST = "127.0.0.1"
COM2_PORT = 9998

def build_test_frame(anomaly=False):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = 1
    frame.fiduciary_role = 0xC001
    frame.veteran_verified = 1
    frame.node_count = 2
    frame.claimant = b"Test Multi-Node Batch Frame"
    frame.statutory_duty = 1
    frame.corporate_defense_valid = 0
    frame.can_be_administered_away = 0

    for i in range(2):
        node = frame.nodes[i]
        if anomaly:
            node.name = bytes([0x80] * 32)
            node.era_year = 1900
            node.territorial_hub = bytes([0x80] * 30)
            node.title_type = 1
        else:
            node.name = f"Node-{i}".encode("utf-8")
            node.era_year = 1900 + i
            node.territorial_hub = b"Fairbanks/Tanana"
            node.title_type = 1

    return bytes(frame)

def test_roundtrip(sock, frame_bytes, expected_flags):
    assert len(frame_bytes) == ctypes.sizeof(SovereignAuditFrame), f"Bad frame length: {len(frame_bytes)}"
    sock.sendall(frame_bytes)
    resp_raw = sock.recv(ctypes.sizeof(SovereignResponseFrame))
    assert len(resp_raw) == ctypes.sizeof(SovereignResponseFrame), f"Short response: {len(resp_raw)}"
    
    resp = SovereignResponseFrame.from_buffer_copy(resp_raw)
    assert resp.magic == SOVA_MAGIC, f"Bad magic: {hex(resp.magic)}"
    assert resp.status_code == SOVR_STATUS_SUCCESS, f"Bad status: {hex(resp.status_code)}"
    assert resp.flags == expected_flags, f"Flag mismatch! Got: {hex(resp.flags)}, Expected: {hex(expected_flags)}"
    return resp

def main():
    print(f"[*] Connecting to seL4 COM2 at {COM2_HOST}:{COM2_PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((COM2_HOST, COM2_PORT))

    try:
        # Test 1: Normal Batch Frame -> Flag 0x0001 (STATUTORY_DUTY)
        frame_normal = build_test_frame(anomaly=False)
        r1 = test_roundtrip(s, frame_normal, expected_flags=SOVR_FLAG_STATUTORY_DUTY)
        print(f"[+] Normal Batch Frame verified -> Flags: {hex(r1.flags)}")

        time.sleep(0.1)

        # Test 2: Anomalous Frame -> Flag 0x0009 (STATUTORY_DUTY | ANOMALY_DETECTED)
        frame_anom = build_test_frame(anomaly=True)
        r2 = test_roundtrip(s, frame_anom, expected_flags=(SOVR_FLAG_STATUTORY_DUTY | SOVR_FLAG_ANOMALY_DETECTED))
        print(f"[+] Anomalous Batch Frame verified -> Flags: {hex(r2.flags)}")

        print("[+] Dynamic anomaly and multi-node batch evaluation verified cleanly.")
    finally:
        s.close()

if __name__ == "__main__":
    main()
