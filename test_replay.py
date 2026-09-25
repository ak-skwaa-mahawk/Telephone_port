#!/usr/bin/env python3
import socket
import sys
import ctypes
import time
from audit_contract import SovereignResponseFrame, SOVR_STATUS_SUCCESS, SOVR_STATUS_ERR_REPLAY
from test_quorum import build_test_frame

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

def run_adversarial_suite():
    print(f"[*] Connecting to seL4 COM2 ({HOST}:{PORT})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    base_seq = int(time.time()) + 1000

    # Phase 1: Legitimate forward sequence frame
    print(f"[*] Phase 1: Dispatching legitimate forward frame (sequence_id = {base_seq})...")
    f1 = build_test_frame(seq_id=base_seq, quorum_count=3, signer_bitmap=0x07)
    r1 = send_frame(sock, f1)
    print(f"[+] Phase 1 response: Status 0x{r1.status_code:04x}, Flags 0x{r1.flags:04x}")
    assert r1.status_code == SOVR_STATUS_SUCCESS, f"Expected 0x0000, got 0x{r1.status_code:04x}"

    # Phase 2: Duplicate sequence replay attack
    print(f"[*] Phase 2: Injecting identical duplicate replay frame (sequence_id = {base_seq})...")
    f2 = build_test_frame(seq_id=base_seq, quorum_count=3, signer_bitmap=0x07)
    r2 = send_frame(sock, f2)
    print(f"[+] Phase 2 response: Status 0x{r2.status_code:04x}, Flags 0x{r2.flags:04x}")
    assert r2.status_code == SOVR_STATUS_ERR_REPLAY, f"Expected 0xE002, got 0x{r2.status_code:04x}"

    # Phase 3: Retroverted past sequence replay attack
    print(f"[*] Phase 3: Injecting retroverted sequence frame (sequence_id = {base_seq - 1})...")
    f3 = build_test_frame(seq_id=base_seq - 1, quorum_count=3, signer_bitmap=0x07)
    r3 = send_frame(sock, f3)
    print(f"[+] Phase 3 response: Status 0x{r3.status_code:04x}, Flags 0x{r3.flags:04x}")
    assert r3.status_code == SOVR_STATUS_ERR_REPLAY, f"Expected 0xE002, got 0x{r3.status_code:04x}"

    sock.close()
    print("[+] ALL REPLAY ADVERSARIAL PHASES PASSED.")

if __name__ == "__main__":
    run_adversarial_suite()
