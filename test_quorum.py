#!/usr/bin/env python3
import socket
import sys
import ctypes
import time
from cryptography.hazmat.primitives.asymmetric import ed25519

def get_dynamic_seq():
    if not hasattr(get_dynamic_seq, "val"):
        get_dynamic_seq.val = int(time.time()) + 200000
    get_dynamic_seq.val += 1
    return get_dynamic_seq.val

from audit_contract import (
    SovereignAuditFrame, SovereignResponseFrame,
    SOVR_MAGIC, SOVR_VERSION, ROLE_FIDUCIARY_PR,
    SOVR_STATUS_SUCCESS, SOVR_STATUS_ERR_QUORUM,
    SOVR_FLAG_QUORUM_VERIFIED
)
from sovereign_pseudonyms import SOVR_ROOT_PUBKEYS

HOST = "127.0.0.1"
PORT = 9998

# Deterministic private seeds corresponding to the 4 committee root identities
COMMITTEE_SEEDS = [
    b"\x11" * 32,  # Node U Esq
    b"\x22" * 32,  # Lineage Root
    b"\x33" * 32,  # Fed Trust
    b"\x44" * 32   # Corp Sentry
]
COMMITTEE_PRIVKEYS = [ed25519.Ed25519PrivateKey.from_private_bytes(seed) for seed in COMMITTEE_SEEDS]

def send_frame(sock, frame):
    sock.sendall(bytes(frame))
    resp_raw = b""
    while len(resp_raw) < ctypes.sizeof(SovereignResponseFrame):
        chunk = sock.recv(ctypes.sizeof(SovereignResponseFrame) - len(resp_raw))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        resp_raw += chunk
    return SovereignResponseFrame.from_buffer_copy(resp_raw)

def build_test_frame(seq_id, quorum_count=3, signer_bitmap=0x07, corrupt_keys=False, corrupt_sig=False):
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
    frame.dockets[0].value = b"4FA-23-01878PR-AK-SUPERIOR"[:31]
    frame.nodes[0].name = b"Dahzhit (Dehjalti')"[:31]
    frame.nodes[0].era_year = 1795
    frame.nodes[0].territorial_hub = b"Yukon / Porcupine"[:23]
    frame.nodes[0].title_type = 1

    frame.quorum_count = quorum_count
    frame.signer_bitmap = signer_bitmap

    # Message slice to sign is exactly the first 320 bytes
    message_block = bytes(frame)[:320]

    witness_idx = 0
    for bit in range(4):
        if signer_bitmap & (1 << bit):
            if witness_idx < quorum_count:
                priv = COMMITTEE_PRIVKEYS[bit]
                pub_bytes = priv.public_key().public_bytes_raw()
                sig_bytes = priv.sign(message_block)

                if corrupt_keys:
                    pub_bytes = b"\x00" * 32
                if corrupt_sig:
                    sig_bytes = b"\xff" * 64

                for i in range(32):
                    frame.witnesses[witness_idx].signer_pubkey[i] = pub_bytes[i]
                for i in range(64):
                    frame.witnesses[witness_idx].signature[i] = sig_bytes[i]

                witness_idx += 1

    return frame

def main():
    print(f"[*] Connecting to seL4 COM2 ({HOST}:{PORT})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # Phase 1: Sub-threshold quorum (quorum_count=2, bitmap=0x03) -> Expect 0xE004
    print("[*] Phase 1: Sub-threshold quorum (quorum_count=2, bitmap=0x03)...")
    f1 = build_test_frame(seq_id=get_dynamic_seq(), quorum_count=2, signer_bitmap=0x03)
    r1 = send_frame(sock, f1)
    print(f"[+] Phase 1 response: Status 0x{r1.status_code:04x}, Flags 0x{r1.flags:04x}")
    assert r1.status_code == SOVR_STATUS_ERR_QUORUM, f"Expected 0xE004, got 0x{r1.status_code:04x}"

    # Phase 2: Popcount mismatch (quorum_count=3, bitmap=0x01) -> Expect 0xE004
    print("[*] Phase 2: Popcount mismatch (quorum_count=3, bitmap=0x01)...")
    f2 = build_test_frame(seq_id=get_dynamic_seq(), quorum_count=3, signer_bitmap=0x01)
    r2 = send_frame(sock, f2)
    print(f"[+] Phase 2 response: Status 0x{r2.status_code:04x}, Flags 0x{r2.flags:04x}")
    assert r2.status_code == SOVR_STATUS_ERR_QUORUM, f"Expected 0xE004, got 0x{r2.status_code:04x}"

    # Phase 3: Corrupted public keys -> Expect 0xE004
    print("[*] Phase 3: Corrupted public keys (quorum_count=3, bitmap=0x07, key=\\x00)...")
    f3 = build_test_frame(seq_id=get_dynamic_seq(), quorum_count=3, signer_bitmap=0x07, corrupt_keys=True)
    r3 = send_frame(sock, f3)
    print(f"[+] Phase 3 response: Status 0x{r3.status_code:04x}, Flags 0x{r3.flags:04x}")
    assert r3.status_code == SOVR_STATUS_ERR_QUORUM, f"Expected 0xE004, got 0x{r3.status_code:04x}"

    # Phase 4: Corrupted signature -> Expect 0xE004
    print("[*] Phase 4: Corrupted Ed25519 signature (quorum_count=3, bitmap=0x07, sig=\\xFF)...")
    f4 = build_test_frame(seq_id=get_dynamic_seq(), quorum_count=3, signer_bitmap=0x07, corrupt_sig=True)
    r4 = send_frame(sock, f4)
    print(f"[+] Phase 4 response: Status 0x{r4.status_code:04x}, Flags 0x{r4.flags:04x}")
    assert r4.status_code == SOVR_STATUS_ERR_QUORUM, f"Expected 0xE004, got 0x{r4.status_code:04x}"

    # Phase 5: Valid threshold quorum (3 of 4: Node U Esq + Lineage Root + Fed Trust) -> Expect 0x0000, 0x0011
    print("[*] Phase 5: Authorized 3-of-4 triad with valid Ed25519 signatures...")
    f5 = build_test_frame(seq_id=get_dynamic_seq(), quorum_count=3, signer_bitmap=0x07)
    r5 = send_frame(sock, f5)
    print(f"[+] Phase 5 response: Status 0x{r5.status_code:04x}, Flags 0x{r5.flags:04x}")
    assert r5.status_code == SOVR_STATUS_SUCCESS, f"Expected 0x0000, got 0x{r5.status_code:04x}"
    assert (r5.flags & SOVR_FLAG_QUORUM_VERIFIED) != 0, "Quorum verified flag missing"

    # Phase 6: Valid supermajority quorum (4 of 4) -> Expect 0x0000, 0x0011
    print("[*] Phase 6: Authorized 4-of-4 committee with valid Ed25519 signatures...")
    f6 = build_test_frame(seq_id=get_dynamic_seq(), quorum_count=4, signer_bitmap=0x0F)
    r6 = send_frame(sock, f6)
    print(f"[+] Phase 6 response: Status 0x{r6.status_code:04x}, Flags 0x{r6.flags:04x}")
    assert r6.status_code == SOVR_STATUS_SUCCESS, f"Expected 0x0000, got 0x{r6.status_code:04x}"
    assert (r6.flags & SOVR_FLAG_QUORUM_VERIFIED) != 0, "Quorum verified flag missing"

    sock.close()
    print("[+] ALL ADVERSARIAL & ED25519 SIGNATURE PHASES PASSED.")

if __name__ == "__main__":
    main()
