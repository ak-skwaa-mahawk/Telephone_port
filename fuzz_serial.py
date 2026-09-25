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

def recv_response(sock, timeout=0.6):
    raw = b""
    start_time = time.time()
    while len(raw) < RESP_SIZE:
        remaining = timeout - (time.time() - start_time)
        if remaining <= 0:
            break
        ready = select.select([sock], [], [], max(0.01, remaining))
        if not ready[0]:
            continue
        chunk = sock.recv(RESP_SIZE - len(raw))
        if not chunk:
            break
        raw += chunk
    if len(raw) == RESP_SIZE:
        return SovereignResponseFrame.from_buffer_copy(raw)
    return None

def drain_socket(sock, drain_timeout=0.2):
    drained_bytes = 0
    while True:
        ready = select.select([sock], [], [], drain_timeout)
        if ready[0]:
            chunk = sock.recv(4096)
            if not chunk:
                break
            drained_bytes += len(chunk)
        else:
            break
    return drained_bytes

def run_fuzz_campaign():
    print(f"[*] Initializing adversarial serial fuzzer on {HOST}:{PORT}...")
    sock = connect_com2()
    seq_id = int(time.time()) + 130000

    dummy = build_test_frame(seq_id=1, quorum_count=3, signer_bitmap=0x07)
    frame_cls = type(dummy)

    quorum_offset = frame_cls.quorum_count.offset if hasattr(frame_cls, 'quorum_count') else 28
    bitmap_offset = frame_cls.signer_bitmap.offset if hasattr(frame_cls, 'signer_bitmap') else 29
    witness_offset = frame_cls.witnesses.offset
    w_size = ctypes.sizeof(dummy.witnesses[0])
    w_cls = type(dummy.witnesses[0])

    sig_offset = 0
    pk_offset = 64
    for field_name, _ in w_cls._fields_:
        attr = getattr(w_cls, field_name)
        if "sig" in field_name.lower():
            sig_offset = attr.offset
        elif any(k in field_name.lower() for k in ["pub", "key", "root"]):
            pk_offset = attr.offset

    # ------------------------------------------------------------------
    # Stage 1: Partial Frame Truncation & Buffer Drain Invariant
    # ------------------------------------------------------------------
    print("\n[+] Stage 1: Partial Frame Truncation & Buffer Drain Invariant")
    truncation_lengths = [1, 16, 64, 319, 320, 512, 1024, 1151]
    
    for length in truncation_lengths:
        seq_id += 1
        frame = build_test_frame(seq_id=seq_id, quorum_count=3, signer_bitmap=0x07)
        raw_truncated = bytes(frame)[:length]
        
        sock.sendall(raw_truncated)
        resp = recv_response(sock, timeout=0.1)
        if resp is not None:
            print(f"[-] Premature frame dispatch on truncated fragment ({length} bytes): 0x{resp.status_code:04x}")
            sys.exit(1)

        pad_len = FRAME_SIZE - length
        sock.sendall(b"\xFF" * pad_len)
        resp = recv_response(sock, timeout=0.6)
        assert resp is not None, f"Rootserver did not respond after completing 1152 bytes at len {length}"
        print(f"    Truncated {length:4d} bytes -> Held correctly, completed frame returned 0x{resp.status_code:04x}")

    # ------------------------------------------------------------------
    # Stage 2: Targeted Gate Fuzzing (100 Iterations across Rejection Gates)
    # ------------------------------------------------------------------
    print("\n[+] Stage 2: Targeted Gate Fuzzing (100 Iterations across Rejection Gates)")
    rejections = 0
    random.seed(0x5056524E)

    for i in range(100):
        seq_id += 1
        valid_frame = bytes(build_test_frame(seq_id=seq_id, quorum_count=3, signer_bitmap=0x07))
        mutable = bytearray(valid_frame)

        gate_mode = i % 4
        if gate_mode == 0:
            w_idx = random.randint(0, 2)
            sig_s_high = witness_offset + w_idx * w_size + sig_offset + 63
            mutable[sig_s_high] |= 0x80
        elif gate_mode == 1:
            w_idx = random.randint(0, 2)
            pk_start = witness_offset + w_idx * w_size + pk_offset
            for b in range(32):
                mutable[pk_start + b] = 0xEE
        elif gate_mode == 2:
            mutable[quorum_offset] = random.choice([0, 1, 2])
        else:
            mutable[bitmap_offset] = random.choice([0x01, 0x02, 0x04, 0x08, 0x03, 0x05, 0x0A])

        sock.sendall(mutable)
        resp = recv_response(sock, timeout=0.5)

        if resp is None:
            rejections += 1
        else:
            if resp.status_code == SOVR_STATUS_SUCCESS:
                print(f"[-] CRITICAL: Gate bypassed at iteration {i} (mode {gate_mode})! Status: 0x{resp.status_code:04x}")
                sys.exit(1)
            else:
                rejections += 1

    print(f"    Completed 100/100 gate mutations: {rejections} rejected cleanly.")

    # ------------------------------------------------------------------
    # Stage 3: Noise Flooding & Boundary Resynchronization
    # ------------------------------------------------------------------
    print("\n[+] Stage 3: Noise Flooding & Boundary Resynchronization")
    for blocks in [1, 2]:
        for _ in range(blocks):
            garbage = bytes(random.getrandbits(8) for _ in range(FRAME_SIZE))
            sock.sendall(garbage)
            resp = recv_response(sock, timeout=0.6)
            assert resp is not None and resp.status_code != SOVR_STATUS_SUCCESS

    print("    Aligned noise bursts rejected without deadlock.")

    # Flood 2 blocks of null bytes one frame at a time to keep pipe synchronized
    for _ in range(2):
        sock.sendall(b"\x00" * FRAME_SIZE)
        resp = recv_response(sock, timeout=0.6)
        assert resp is not None and resp.status_code != SOVR_STATUS_SUCCESS

    print(f"    Null byte flood (2304 bytes) rejected cleanly.")

    # ------------------------------------------------------------------
    # Stage 4: Post-Stress Liveness & Invariant Confirmation
    # ------------------------------------------------------------------
    print("\n[+] Stage 4: Verifying Microkernel Liveness Post-Fuzz...")
    drained = drain_socket(sock, drain_timeout=0.3)
    if drained > 0:
        print(f"    Drained {drained} trailing bytes before liveness check.")

    seq_id += 500
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
