#!/usr/bin/env python3
import socket
import time
import ctypes
import sys

from audit_contract import (
    SovereignAuditFrame,
    SovereignResponseFrame,
    SOVA_MAGIC,
    SOVR_STATUS_SUCCESS
)

SOVR_MAGIC = 0x534F5652
TITLE_ABORIGINAL_SOVEREIGN   = 0x0001
SOVR_FLAG_STATUTORY_DUTY     = (1 << 0)  # 0x0001
SOVR_FLAG_CORP_DEFENSE_VALID = (1 << 1)  # 0x0002
SOVR_FLAG_CAN_BE_ADMINISTERED= (1 << 2)  # 0x0004
SOVR_FLAG_ANOMALY_DETECTED   = (1 << 3)  # 0x0008

COM2_HOST = "127.0.0.1"
COM2_PORT = 9998

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Socket closed unexpectedly; received {len(buf)} of {n} bytes")
        buf.extend(chunk)
    return bytes(buf)

def build_test_frame(anomaly=False):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = 1
    frame.fiduciary_role = 0xC001
    frame.veteran_verified = 1
    frame.node_count = 2
    frame.claimant = b"Test Multi-Node Sovereign Batch"
    
    # Satisfy judicial order invariant using ctypes .value assignment
    frame.dockets[0].value = b"4FA-23-01878PR-IN-THE-SUPERIOR-COURT-OF-ALASKA"
    frame.dockets[1].value = b"3AN-24-00123CI"

    for i in range(2):
        node = frame.nodes[i]
        node.title_type = TITLE_ABORIGINAL_SOVEREIGN
        if anomaly:
            anom_payload = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            node.name = anom_payload[:32]
            node.era_year = int.from_bytes(anom_payload[32:34], "little")
            node.territorial_hub = anom_payload[34:64]
        else:
            node.name = f"Node-{i}".encode("utf-8")
            node.era_year = 1900 + i
            node.territorial_hub = b"Fairbanks/Tanana"

    return bytes(frame)

def test_roundtrip(sock, frame_bytes):
    assert len(frame_bytes) == ctypes.sizeof(SovereignAuditFrame), f"Bad frame length: {len(frame_bytes)}"
    sock.sendall(frame_bytes)
    resp_raw = recv_exact(sock, ctypes.sizeof(SovereignResponseFrame))
    
    resp = SovereignResponseFrame.from_buffer_copy(resp_raw)
    assert resp.magic == SOVA_MAGIC, f"Bad magic: {hex(resp.magic)}"
    assert resp.status_code == SOVR_STATUS_SUCCESS, f"Bad status: {hex(resp.status_code)}"
    return resp

def main():
    print(f"[*] Connecting to seL4 COM2 at {COM2_HOST}:{COM2_PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((COM2_HOST, COM2_PORT))

    try:
        # Test 1: Normal Multi-Node Batch Frame
        frame_normal = build_test_frame(anomaly=False)
        r1 = test_roundtrip(s, frame_normal)
        print(f"[+] Normal Batch Frame verified -> Status: {hex(r1.status_code)}, Flags: {hex(r1.flags)}")
        assert (r1.flags & SOVR_FLAG_STATUTORY_DUTY) != 0, f"Statutory duty missing, got {hex(r1.flags)}"
        assert (r1.flags & SOVR_FLAG_ANOMALY_DETECTED) == 0, f"Anomaly flagged prematurely on normal frame: {hex(r1.flags)}"

        time.sleep(0.1)

        # Test 2: Anomalous Multi-Node Batch Frame
        frame_anom = build_test_frame(anomaly=True)
        r2 = test_roundtrip(s, frame_anom)
        print(f"[+] Anomalous Batch Frame verified -> Status: {hex(r2.status_code)}, Flags: {hex(r2.flags)}")
        assert (r2.flags & SOVR_FLAG_STATUTORY_DUTY) != 0, f"Statutory duty missing on anomaly frame: {hex(r2.flags)}"
        assert (r2.flags & SOVR_FLAG_ANOMALY_DETECTED) != 0, f"Anomaly flag missing on anomalous frame: {hex(r2.flags)}"

        print("[+] Dynamic anomaly and multi-node batch evaluation verified cleanly.")
    finally:
        s.close()

if __name__ == "__main__":
    main()
