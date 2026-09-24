#!/usr/bin/env python3
import asyncio
import websockets
import json
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
SOVR_FLAG_STATUTORY_DUTY     = (1 << 0)
SOVR_FLAG_ANOMALY_DETECTED   = (1 << 3)

WS_URI = "ws://127.0.0.1:8765"
UDP_TARGET = ("127.0.0.1", 9999)
COM2_HOST = "127.0.0.1"
COM2_PORT = 9998

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)

def build_frame(anomaly=False):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = 1
    frame.fiduciary_role = 0xC001
    frame.veteran_verified = 1
    frame.node_count = 2
    frame.claimant = b"Telemetry Broadcaster Integration Attestation"
    frame.dockets[0].value = b"4FA-23-01878PR-IN-THE-SUPERIOR-COURT-OF-ALASKA"
    frame.dockets[1].value = b"3AN-24-00123CI"

    for i in range(2):
        node = frame.nodes[i]
        node.title_type = TITLE_ABORIGINAL_SOVEREIGN
        if anomaly:
            node.name = bytes([127] * 32)
            node.era_year = 0x7F7F
            node.territorial_hub = bytes([127] * 30)
        else:
            node.name = f"Node-{i}".encode("utf-8")
            node.era_year = 1900 + i
            node.territorial_hub = b"Fairbanks/Tanana"
    return bytes(frame)

async def recv_evaluation_frame(ws, timeout=4.0):
    start = time.time()
    while time.time() - start < timeout:
        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
        try:
            payload = json.loads(msg)
            if isinstance(payload, dict) and payload.get("type") == "EVALUATION_FRAME":
                return payload
        except Exception:
            pass
    raise TimeoutError("Timed out awaiting EVALUATION_FRAME")

async def test_pipeline():
    print(f"[*] Connecting to WebSocket broadcaster at {WS_URI}...")
    async with websockets.connect(WS_URI) as ws:
        print("[+] WebSocket client connected.")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((COM2_HOST, COM2_PORT))

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # 1. Normal frame
            s.sendall(build_frame(anomaly=False))
            raw_resp = recv_exact(s, ctypes.sizeof(SovereignResponseFrame))
            udp_sock.sendto(raw_resp, UDP_TARGET)
            
            telemetry = await recv_evaluation_frame(ws)
            print(f"[+] WS Received Normal Frame: raw_flags={telemetry["flags"]["raw"]}")
            assert telemetry["flags"]["anomaly_detected"] is False
            assert "alert" not in telemetry

            time.sleep(0.1)

            # 2. Anomalous frame
            s.sendall(build_frame(anomaly=True))
            raw_resp_anom = recv_exact(s, ctypes.sizeof(SovereignResponseFrame))
            udp_sock.sendto(raw_resp_anom, UDP_TARGET)

            telemetry_anom = await recv_evaluation_frame(ws)
            print(f"[+] WS Received Anomaly Frame: raw_flags={telemetry_anom["flags"]["raw"]}")
            assert telemetry_anom["flags"]["anomaly_detected"] is True
            assert telemetry_anom["alert"]["level"] == "CRITICAL"
            print(f"[+] Broadcasted Alert Message: {telemetry_anom["alert"]["message"]}")

            print("[+] Real-time WebSocket anomaly broadcasting verified.")
        finally:
            s.close()
            udp_sock.close()

if __name__ == "__main__":
    asyncio.run(test_pipeline())
