#!/usr/bin/env python3
"""
test_uplink_relay.py - End-to-End Outbound WSS Relay Uplink & Auth Verification
1. Generates ephemeral TLS certificates.
2. Spawns an authenticated WSS endpoint (127.0.0.1:8766) requiring Bearer Token.
3. Launches mesh_bridge_daemon with MESH_UPLINK_WSS_URL configured.
4. Streams normal and anomalous telemetry to UDP :9999.
5. Asserts remote WSS reception and header authentication.
"""

import asyncio
import json
import logging
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import websockets

EXPECTED_TOKEN = "SOVEREIGN_UPLINK_AUTH_KEY_V1"
RELAY_PORT = 8766
UDP_PORT = 9999

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("test_uplink")

received_payloads = []
auth_verified = asyncio.Event()

def generate_self_signed_cert(cert_path, key_path):
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "1", "-nodes",
        "-subj", "/CN=127.0.0.1"
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

async def wss_relay_handler(websocket):
    # Verify Authorization header
    headers = getattr(websocket, "request_headers", None)
    if headers is None:
        headers = getattr(getattr(websocket, "request", None), "headers", {})
    
    auth_header = headers.get("Authorization", "")
    logger.info(f"[*] Incoming connection with Authorization header: {auth_header}")
    
    if auth_header != f"Bearer {EXPECTED_TOKEN}":
        logger.error("[-] Invalid bearer token. Closing connection.")
        await websocket.close(1008, "Unauthorized")
        return

    logger.info("[+] Uplink bearer token authenticated successfully.")
    auth_verified.set()

    try:
        async for msg in websocket:
            try:
                data = json.loads(msg)
                received_payloads.append(data)
                logger.info(f"[+] Uplink received: {data.get('type')} (flags: {data.get('flags', {}).get('raw')})")
            except Exception as e:
                logger.error(f"[-] Decode error: {e}")
    except websockets.exceptions.ConnectionClosed:
        pass

async def run_pipeline_test():
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = os.path.join(tmpdir, "cert.pem")
        key_file = os.path.join(tmpdir, "key.pem")
        generate_self_signed_cert(cert_file, key_file)

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

        logger.info(f"[*] Starting Mock Authenticated WSS Relay on 127.0.0.1:{RELAY_PORT}...")
        async with websockets.serve(wss_relay_handler, "127.0.0.1", RELAY_PORT, ssl=ssl_ctx):
            
            # Start mesh_bridge_daemon with uplink env vars set
            env = os.environ.copy()
            env["MESH_WS_PORT"] = "8767"
            env["MESH_UDP_PORT"] = str(UDP_PORT)
            env["MESH_UPLINK_WSS_URL"] = f"wss://127.0.0.1:{RELAY_PORT}"
            env["MESH_UPLINK_TOKEN"] = EXPECTED_TOKEN
            env["MESH_UPLINK_VERIFY_TLS"] = "0"

            daemon_proc = subprocess.Popen(
                [sys.executable, "/data/data/com.termux/files/home/Tordial-GS/scripts/mesh_bridge_daemon.py"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            try:
                # Wait for bridge to connect and authenticate
                logger.info("[*] Waiting for bridge daemon to establish authenticated uplink...")
                try:
                    await asyncio.wait_for(auth_verified.wait(), timeout=6.0)
                except TimeoutError:
                    daemon_proc.poll()
                    out, err = daemon_proc.communicate(timeout=1.0)
                    print("--- DAEMON STDOUT ---")
                    print(out.decode("utf-8", errors="ignore"))
                    print("--- DAEMON STDERR ---")
                    print(err.decode("utf-8", errors="ignore"))
                    raise
                logger.info("[+] Daemon uplink verified and connected.")

                # Send Normal evaluation packet over UDP
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                normal_payload = {
                    "type": "EVALUATION_FRAME",
                    "magic": "0x534f5641",
                    "status_code": "0x0000",
                    "flags": {"raw": 1, "statutory_duty": True, "anomaly_detected": False},
                    "root_hash": "de154802cd1da19a38624c54ab004bfb95658243feb72d41b270563e8cb5daea"
                }
                udp_sock.sendto(json.dumps(normal_payload).encode("utf-8"), ("127.0.0.1", UDP_PORT))
                
                # Send Anomaly evaluation packet over UDP
                anomaly_payload = {
                    "type": "EVALUATION_FRAME",
                    "magic": "0x534f5641",
                    "status_code": "0x0000",
                    "flags": {"raw": 9, "statutory_duty": True, "anomaly_detected": True},
                    "root_hash": "de154802cd1da19a38624c54ab004bfb95658243feb72d41b270563e8cb5daea"
                }
                udp_sock.sendto(json.dumps(anomaly_payload).encode("utf-8"), ("127.0.0.1", UDP_PORT))
                udp_sock.close()

                # Await payload reception by the upstream relay
                start = time.time()
                while len(received_payloads) < 2 and time.time() - start < 5.0:
                    await asyncio.sleep(0.1)

                assert len(received_payloads) >= 2, f"Expected 2 payloads, received {len(received_payloads)}"
                
                p0 = received_payloads[0]
                p1 = received_payloads[1]
                assert p0["flags"]["raw"] == 1
                assert p0["flags"]["anomaly_detected"] is False
                assert p1["flags"]["raw"] == 9
                assert p1["flags"]["anomaly_detected"] is True
                assert p1["alert"]["level"] == "CRITICAL"

                print("\n[+] OUTBOUND WSS UPLINK VERIFIED: Bearer Auth, TLS Handshake, and Alert Relay Functional.")
            finally:
                daemon_proc.terminate()
                daemon_proc.wait()

if __name__ == "__main__":
    asyncio.run(run_pipeline_test())
