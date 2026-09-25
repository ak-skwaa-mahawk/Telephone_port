#!/usr/bin/env python3
import socket
import sys
import ctypes
from audit_contract import (
    SovereignAuditFrame, SovereignResponseFrame,
    SOVR_MAGIC, SOVA_MAGIC, SOVR_VERSION, ROLE_FIDUCIARY_PR,
    SOVR_STATUS_SUCCESS, SOVR_STATUS_ERR_QUORUM, SOVR_FLAG_QUORUM_VERIFIED
)

HOST = "127.0.0.1"
PORT = 9998

def send_frame(sock, frame):
    payload = bytes(frame)
    sock.sendall(payload)
    resp_raw = b""
    while len(resp_raw) < ctypes.sizeof(SovereignResponseFrame):
        chunk = sock.recv(ctypes.sizeof(SovereignResponseFrame) - len(resp_raw))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        resp_raw += chunk
    return SovereignResponseFrame.from_buffer_copy(resp_raw)

def build_test_frame(seq_id, quorum_count, signer_bitmap):
    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = SOVR_VERSION
    frame.fiduciary_role = ROLE_FIDUCIARY_PR
    frame.sequence_id = seq_id
    frame.veteran_verified = 1
    frame.statutory_duty = 1
    frame.corporate_defense_valid = 0
    frame.can_be_administered_away = 0
    frame.node_count = 1
    frame.claimant = b"Christopher Carroll"
    frame.dockets[0].value = b"STATE-PROBATE-ORDER-ALASKA"[:31]
    frame.nodes[0].name = b"Dahzhit (Dehjalti')"[:31]
    frame.nodes[0].era_year = 1795
    frame.nodes[0].territorial_hub = b"Yukon / Porcupine"[:23]
    frame.nodes[0].title_type = 1
    frame.quorum_count = quorum_count
    frame.signer_bitmap = signer_bitmap
    return frame

def main():
    print("[*] Connecting to seL4 COM2 (127.0.0.1:9998)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # Phase 1: Sub-threshold quorum (2 of 4) -> Expect 0xE004
    print("[*] Phase 1: Injecting sub-threshold quorum (quorum_count=2, bitmap=0x03)...")
    f1 = build_test_frame(seq_id=100, quorum_count=2, signer_bitmap=0x03)
    r1 = send_frame(sock, f1)
    print(f"[+] Phase 1 response: Status 0x{r1.status_code:04x}, Flags 0x{r1.flags:04x}")
    assert r1.status_code == SOVR_STATUS_ERR_QUORUM, f"Expected 0xE004, got 0x{r1.status_code:04x}"

    # Phase 2: Popcount mismatch (quorum_count=3, bitmap=0x01) -> Expect 0xE004
    print("[*] Phase 2: Injecting popcount mismatch (quorum_count=3, bitmap=0x01)...")
    f2 = build_test_frame(seq_id=101, quorum_count=3, signer_bitmap=0x01)
    r2 = send_frame(sock, f2)
    print(f"[+] Phase 2 response: Status 0x{r2.status_code:04x}, Flags 0x{r2.flags:04x}")
    assert r2.status_code == SOVR_STATUS_ERR_QUORUM, f"Expected 0xE004, got 0x{r2.status_code:04x}"

    # Phase 3: Valid threshold quorum (3 of 4) -> Expect 0x0000, Flags with 0x0010
    print("[*] Phase 3: Injecting valid 3-of-4 quorum (quorum_count=3, bitmap=0x07)...")
    f3 = build_test_frame(seq_id=102, quorum_count=3, signer_bitmap=0x07)
    r3 = send_frame(sock, f3)
    print(f"[+] Phase 3 response: Status 0x{r3.status_code:04x}, Flags 0x{r3.flags:04x}")
    assert r3.status_code == SOVR_STATUS_SUCCESS, f"Expected 0x0000, got 0x{r3.status_code:04x}"
    assert (r3.flags & SOVR_FLAG_QUORUM_VERIFIED) != 0, "Quorum verified flag missing"

    # Phase 4: Valid supermajority quorum (4 of 4) -> Expect 0x0000, Flags with 0x0010
    print("[*] Phase 4: Injecting valid 4-of-4 quorum (quorum_count=4, bitmap=0x0F)...")
    f4 = build_test_frame(seq_id=103, quorum_count=4, signer_bitmap=0x0F)
    r4 = send_frame(sock, f4)
    print(f"[+] Phase 4 response: Status 0x{r4.status_code:04x}, Flags 0x{r4.flags:04x}")
    assert r4.status_code == SOVR_STATUS_SUCCESS, f"Expected 0x0000, got 0x{r4.status_code:04x}"
    assert (r4.flags & SOVR_FLAG_QUORUM_VERIFIED) != 0, "Quorum verified flag missing"

    sock.close()
    print("[+] ALL QUORUM ADVERSARIAL PHASES PASSED.")

if __name__ == "__main__":
    main()
