#!/usr/bin/env python3
import socket
import sys
import ctypes
import time
from audit_contract import (
    SovereignAuditFrame, SovereignResponseFrame,
    SOVR_MAGIC, SOVA_MAGIC, SOVR_VERSION, ROLE_FIDUCIARY_PR,
    SOVR_STATUS_SUCCESS, SOVR_STATUS_REJECT_REPLAY,
    SOVR_FLAG_QUORUM_VERIFIED
)

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

def build_test_frame(sequence_id):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = SOVR_VERSION
    frame.fiduciary_role = ROLE_FIDUCIARY_PR
    frame.sequence_id = sequence_id
    frame.veteran_verified = 1
    frame.statutory_duty = 1
    frame.corporate_defense_valid = 0
    frame.can_be_administered_away = 0
    frame.node_count = 1
    frame.claimant = b"Christopher Carroll"
    frame.dockets[0].value = b"4FA-23-01878PR-AK-SUPERIOR"[:31]
    frame.nodes[0].name = b"Dahzhit (Dehjalti')"[:31]
    frame.nodes[0].era_year = 1795
    frame.nodes[0].territorial_hub = b"Yukon / Porcupine"[:23]
    frame.nodes[0].title_type = 1
    frame.quorum_count = 3
    frame.signer_bitmap = 0x07
    return frame

def run_adversarial_suite():
    print(f"[*] Connecting to seL4 COM2 ({HOST}:{PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Base sequence on monotonic time to guarantee strictly forward progression
    test_seq = int(time.time())

    # Phase 1: Forward legitimate frame
    print(f"[*] Phase 1: Dispatching legitimate forward frame (sequence_id = {test_seq})...")
    resp1 = send_frame(s, build_test_frame(test_seq))
    print(f"[+] Phase 1 response: Status 0x{resp1.status_code:04x}, Flags 0x{resp1.flags:04x}")
    assert resp1.status_code == SOVR_STATUS_SUCCESS, f"Expected 0x0000, got 0x{resp1.status_code:04x}"
    assert (resp1.flags & SOVR_FLAG_QUORUM_VERIFIED) != 0, "Quorum verified flag missing"

    # Phase 2: Duplicate sequence replay
    print(f"[*] Phase 2: Injecting identical duplicate replay frame (sequence_id = {test_seq})...")
    resp2 = send_frame(s, build_test_frame(test_seq))
    print(f"[+] Phase 2 response: Status 0x{resp2.status_code:04x}, Flags 0x{resp2.flags:04x}")
    assert resp2.status_code == SOVR_STATUS_REJECT_REPLAY, f"Expected 0xE002, got 0x{resp2.status_code:04x}"
    assert resp2.flags == 0x0000, "Flags must be cleared on replay"

    # Phase 3: Retroverted sequence
    retro_seq = test_seq - 1
    print(f"[*] Phase 3: Injecting retroverted sequence frame (sequence_id = {retro_seq})...")
    resp3 = send_frame(s, build_test_frame(retro_seq))
    print(f"[+] Phase 3 response: Status 0x{resp3.status_code:04x}, Flags 0x{resp3.flags:04x}")
    assert resp3.status_code == SOVR_STATUS_REJECT_REPLAY, f"Expected 0xE002, got 0x{resp3.status_code:04x}"
    assert resp3.flags == 0x0000, "Flags must be cleared on retroversion"

    s.close()
    print("[+] ALL REPLAY ADVERSARIAL PHASES PASSED.")

if __name__ == "__main__":
    run_adversarial_suite()
