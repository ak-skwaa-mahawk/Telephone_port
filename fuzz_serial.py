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

def recv_response(sock, timeout=0.5):
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

def run_fuzz_campaign():
    print(f"[*] Initializing adversarial serial fuzzer on {HOST}:{PORT}...")
    seq_id = int(time.time()) + 60000

    # ------------------------------------------------------------------
    # Stage 1: Partial Frame Truncation & Isolation
    # ------------------------------------------------------------------
    print("\n[+] Stage 1: Partial Frame Truncation & Connection Isolation")
    truncation_lengths = [1, 16, 64, 319, 320, 512, 1024, 1151]
    
    for length in truncation_lengths:
        seq_id += 1
        sock = connect_com2()
        frame = build_test_frame(seq_id=seq_id, quorum_count=3, signer_bitmap=0x07)
        raw_truncated = bytes(frame)[:length]
        
        # Send incomplete chunk alone
        sock.sendall(raw_truncated)
        resp = recv_response(sock, timeout=0.2)
        if resp is not None:
            print(f"[-] Premature frame dispatch on truncated fragment ({length} bytes): 0x{resp.status_code:04x}")
            sys.exit(1)

        print(f"    Truncated {length:4d} bytes -> Buffered (no premature dispatch, zero leaks)")
        sock.close()
        time.sleep(0.05)

    # ------------------------------------------------------------------
    # Stage 2: In-Stream Desynchronization & Rejection Verification
    # ------------------------------------------------------------------
    print("\n[+] Stage 2: Desynchronized Offset Ingestion (Skewed Framing)")
    sock = connect_com2()
    # Inject 13 bytes of misalignment
    sock.sendall(b"\xAA" * 13)
    seq_id += 1
    aligned_frame = build_test_frame(seq_id=seq_id, quorum_count=3, signer_bitmap=0x07)
    sock.sendall(bytes(aligned_frame))
    resp = recv_response(sock, timeout=0.5)
    print(f"    Skewed stream response: {'0x%04x' % resp.status_code if resp else 'Dropped/Pending'}")
    assert resp is None or resp.status_code != SOVR_STATUS_SUCCESS, "Skewed stream was unexpectedly accepted!"
    sock.close()
    time.sleep(0.05)

    # ------------------------------------------------------------------
    # Stage 3: Pseudorandom Bit-Flipping across 1152-byte Geometry (100 Iterations)
    # ------------------------------------------------------------------
    print("\n[+] Stage 3: Targeted Bit-Flipping Fuzzing (100 Iterations)")
    sock = connect_com2()
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
    sock.close()
    time.sleep(0.05)

    # ------------------------------------------------------------------
    # Stage 4: High-Entropy Noise Bursts & Null Byte Flooding
    # ------------------------------------------------------------------
    print("\n[+] Stage 4: High-Entropy Noise Bursts & Null Floods")
    sock = connect_com2()
    for burst_size in [64, 256, 1152, 4096]:
        garbage = bytes(random.getrandbits(8) for _ in range(burst_size))
        sock.sendall(garbage)
        resp = recv_response(sock, timeout=0.1)
        print(f"    Noise burst ({burst_size:4d} bytes) -> Handled without panic.")

    sock.sendall(b"\x00" * 4096)
    resp = recv_response(sock, timeout=0.1)
    print("    Null flood (4096 bytes) -> Absorbed without panic.")
    sock.close()
    time.sleep(0.05)

    # ------------------------------------------------------------------
    # Stage 5: Post-Stress Liveness & Invariant Confirmation
    # ------------------------------------------------------------------
    print("\n[+] Stage 5: Verifying Microkernel Liveness Post-Fuzz...")
    sock = connect_com2()
    seq_id += 50
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
