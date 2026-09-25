#!/usr/bin/env python3
import socket
import select
import random
import time
import ctypes
import sys

from audit_contract import (
    SovereignResponseFrame,
    SOVR_STATUS_SUCCESS,
    SOVR_STATUS_REJECT_REPLAY,
)
from test_quorum import build_test_frame

HOST = "127.0.0.1"
PORT = 9998
FRAME_SIZE = 1152
RESP_SIZE = ctypes.sizeof(SovereignResponseFrame)

def connect_com2():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect((HOST, PORT))
    return sock

def recv_response(sock, timeout=0.4):
    ready = select.select([sock], [], [], timeout)
    if not ready[0]:
        return None
    raw = b""
    while len(raw) < RESP_SIZE:
        ready = select.select([sock], [], [], timeout)
        if not ready[0]:
            break
        chunk = sock.recv(RESP_SIZE - len(raw))
        if not chunk:
            break
        raw += chunk
    if len(raw) == RESP_SIZE:
        return SovereignResponseFrame.from_buffer_copy(raw)
    return None

def drain_socket(sock):
    """Drain any pending bytes on the socket."""
    while True:
        ready = select.select([sock], [], [], 0.05)
        if ready[0]:
            chunk = sock.recv(1024)
            if not chunk:
                break
        else:
            break

def run_fuzz_campaign():
    print(f"[*] Initializing adversarial serial fuzzer on {HOST}:{PORT}...")
    sock = connect_com2()
    seq_id = int(time.time()) + 70000

    # ------------------------------------------------------------------
    # Stage 1: Partial Frame Truncation & Drained Alignment
    # ------------------------------------------------------------------
    print("\n[+] Stage 1: Partial Frame Truncation & Buffer Drain Invariant")
    truncation_lengths = [1, 16, 64, 319, 320, 512, 1024, 1151]
    
    for length in truncation_lengths:
        seq_id += 1
        frame = build_test_frame(seq_id=seq_id, quorum_count=3, signer_bitmap=0x07)
        raw_truncated = bytes(frame)[:length]
        
        # 1. Send truncated chunk
        sock.sendall(raw_truncated)
        resp = recv_response(sock, timeout=0.1)
        if resp is not None:
            print(f"[-] Premature frame dispatch on truncated fragment ({length} bytes): 0x{resp.status_code:04x}")
            sys.exit(1)

        # 2. Pad remainder to complete 1152-byte boundary and clear accumulator
        pad_len = FRAME_SIZE - length
        sock.sendall(b"\xFF" * pad_len)
        resp = recv_response(sock, timeout=0.5)
        assert resp is not None, f"Rootserver did not reject padded garbage at len {length}"
        assert resp.status_code != SOVR_STATUS_SUCCESS, f"Padded garbage was accepted! (0x{resp.status_code:04x})"

        print(f"    Truncated {length:4d} bytes -> Held correctly, padded flush returned 0x{resp.status_code:04x}")

    # ------------------------------------------------------------------
    # Stage 2: Pseudorandom Bit-Flipping across 1152-byte Geometry (100 Iterations)
    # ------------------------------------------------------------------
    print("\n[+] Stage 2: Targeted Bit-Flipping Fuzzing (100 Iterations)")
    rejections = 0
    random.seed(0x5056524E)

    for i in range(100):
        seq_id += 1
        valid_frame = bytes(build_test_frame(seq_id=seq_id, quorum_count=3, signer_bitmap=0x07))
        mutable = bytearray(valid_frame)

        # Mutate 1 to 5 random bits
        flips = random.randint(1, 5)
        for _ in range(flips):
            target_byte = random.randint(0, FRAME_SIZE - 1)
            target_bit = 1 << random.randint(0, 7)
            mutable[target_byte] ^= target_bit

        sock.sendall(mutable)
        resp = recv_response(sock, timeout=0.4)

        if resp is None:
            rejections += 1
        else:
            if resp.status_code == SOVR_STATUS_SUCCESS:
                print(f"[-] CRITICAL: Mutated frame accepted at iteration {i}!")
                sys.exit(1)
            else:
                rejections += 1

    print(f"    Completed 100/100 mutations: {rejections} rejected or dropped cleanly.")

    # ------------------------------------------------------------------
    # Stage 3: High-Entropy Noise Bursts & Resynchronization
    # ------------------------------------------------------------------
    print("\n[+] Stage 3: Noise Flooding & Boundary Resynchronization")
    # Send random noise aligned to frame blocks
    for blocks in [1, 2, 4]:
        garbage = bytes(random.getrandbits(8) for _ in range(FRAME_SIZE * blocks))
        sock.sendall(garbage)
        for _ in range(blocks):
            resp = recv_response(sock, timeout=0.3)
            assert resp is not None and resp.status_code != SOVR_STATUS_SUCCESS

    print("    Aligned noise bursts rejected without deadlock.")

    # Send 4096 null bytes padded to 1152 boundary
    null_pad = ((4096 + FRAME_SIZE - 1) // FRAME_SIZE) * FRAME_SIZE
    sock.sendall(b"\x00" * null_pad)
    for _ in range(null_pad // FRAME_SIZE):
        resp = recv_response(sock, timeout=0.3)
        assert resp is not None and resp.status_code != SOVR_STATUS_SUCCESS

    print(f"    Null byte flood ({null_pad} bytes) rejected cleanly.")

    # ------------------------------------------------------------------
    # Stage 4: Post-Stress Liveness & Invariant Confirmation
    # ------------------------------------------------------------------
    print("\n[+] Stage 4: Verifying Microkernel Liveness Post-Fuzz...")
    drain_socket(sock)
    seq_id += 100
    final_frame = build_test_frame(seq_id=seq_id, quorum_count=3, signer_bitmap=0x07)
    sock.sendall(bytes(final_frame))
    final_resp = recv_response(sock, timeout=1.5)

    if final_resp and final_resp.status_code == SOVR_STATUS_SUCCESS:
        print(f"[+] LIVENESS CONFIRMED: Status 0x{final_resp.status_code:04x}, Flags 0x{final_resp.flags:04x}")
        print("[+] ALL ADVERSARIAL SERIAL FUZZING PHASES SURVIVED.")
    else:
        status_str = f"0x{final_resp.status_code:04x}" if final_resp else "None"
        print(f"[-] FAILED post-stress liveness check (Status: {status_str})")
        sys.exit(1)

    sock.close()

if __name__ == "__main__":
    run_fuzz_campaign()
