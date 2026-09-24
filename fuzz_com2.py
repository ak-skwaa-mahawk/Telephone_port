#!/usr/bin/env python3
import time
import socket
import ctypes
import sys
from audit_contract import (
    serialize_estate_to_frame,
    compute_frame_binary_hash,
    SovereignAuditFrame,
    SovereignResponseFrame,
    SOVA_MAGIC,
    SOVR_STATUS_SUCCESS,
    SOVR_STATUS_ERR_MAGIC,
    SOVR_STATUS_ERR_BOUNDS
)

HOST = "127.0.0.1"
PORT = 9998
RESP_LEN = ctypes.sizeof(SovereignResponseFrame)
NODE_COUNT_OFFSET = SovereignAuditFrame.node_count.offset

def read_exact(sock, length):
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionResetError("Socket closed during read")
        buf.extend(chunk)
    return bytes(buf)

def run_fuzzer(cycles=50):
    valid_frame = serialize_estate_to_frame()
    valid_payload = bytearray(bytes(valid_frame))
    expected_hash = compute_frame_binary_hash(valid_frame)

    print(f"[*] Connecting fuzzer to seL4 COM2 at {HOST}:{PORT}...")
    print(f"[*] Dynamic SovereignAuditFrame.node_count offset: {NODE_COUNT_OFFSET}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    sock.connect((HOST, PORT))

    print(f"[*] Executing {cycles} fault-injection sequences...")
    stats = {"magic_err": 0, "bounds_err": 0, "valid_ok": 0}

    for i in range(1, cycles + 1):
        # 1. Test Magic Mutation
        mutated_magic = bytearray(valid_payload)
        mutated_magic[0:4] = b"BAD!"
        sock.sendall(mutated_magic)
        resp = SovereignResponseFrame.from_buffer_copy(read_exact(sock, RESP_LEN))
        assert resp.magic == SOVA_MAGIC, f"Iter {i}: Bad response magic on magic fault: {hex(resp.magic)}"
        assert resp.status_code == SOVR_STATUS_ERR_MAGIC, f"Iter {i}: Expected ERR_MAGIC, got {hex(resp.status_code)}"
        stats["magic_err"] += 1

        # 2. Test Node Count Overflow (> 16)
        mutated_nodes = bytearray(valid_payload)
        mutated_nodes[NODE_COUNT_OFFSET:NODE_COUNT_OFFSET + 2] = (255).to_bytes(2, byteorder="little")
        sock.sendall(mutated_nodes)
        resp = SovereignResponseFrame.from_buffer_copy(read_exact(sock, RESP_LEN))
        assert resp.magic == SOVA_MAGIC, f"Iter {i}: Bad response magic on bounds fault: {hex(resp.magic)}"
        assert resp.status_code == SOVR_STATUS_ERR_BOUNDS, f"Iter {i}: Expected ERR_BOUNDS, got {hex(resp.status_code)}"
        stats["bounds_err"] += 1

        # 3. Test Interleaved Valid Frame (Verify recovery & state alignment)
        sock.sendall(valid_payload)
        resp = SovereignResponseFrame.from_buffer_copy(read_exact(sock, RESP_LEN))
        assert resp.magic == SOVA_MAGIC, f"Iter {i}: Bad response magic on valid recovery: {hex(resp.magic)}"
        assert resp.status_code == SOVR_STATUS_SUCCESS, f"Iter {i}: Expected SUCCESS, got {hex(resp.status_code)}"
        assert bytes(resp.root_hash).hex() == expected_hash, f"Iter {i}: Root hash mismatch on valid recovery"
        stats["valid_ok"] += 1

        if i % 10 == 0:
            print(f"  -> Cycle {i}/{cycles} passed: fault injection handled cleanly")

    sock.close()

    print("\n=== FAULT-INJECTION & FUZZING COMPLETED ===")
    print(f"  Total Mutations Tested : {cycles * 2}")
    print(f"  Magic Fault Rejections : {stats['magic_err']}")
    print(f"  Bounds Fault Rejections: {stats['bounds_err']}")
    print(f"  Valid Recovery Passes  : {stats['valid_ok']}")
    print(f"  Microkernel Stability  : 100% (No stalls, zero desync)")

if __name__ == "__main__":
    run_fuzzer()
