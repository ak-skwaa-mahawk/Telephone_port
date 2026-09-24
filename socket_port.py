#!/usr/bin/env python3
import socket
import argparse
import ctypes
from audit_contract import (
    serialize_estate_to_frame,
    compute_frame_binary_hash,
    SovereignAuditFrame,
    SovereignResponseFrame,
    SOVA_MAGIC,
    SOVR_STATUS_SUCCESS,
    SOVR_STATUS_ERR_MAGIC,
    SOVR_STATUS_ERR_BOUNDS,
    SOVR_FLAG_STATUTORY_DUTY,
    SOVR_FLAG_CORP_DEFENSE_VALID,
    SOVR_FLAG_CAN_BE_ADMINISTERED
)

DEFAULT_HOST = "127.0.0.1"
COM2_PORT = 9998
DEFAULT_PORT = 9999

def stream_frame_to_com2(frame: SovereignAuditFrame, host=DEFAULT_HOST, port=COM2_PORT, label="COM2 Stream"):
    payload = bytes(frame)
    expected_hash = compute_frame_binary_hash(frame)
    print(f"\n[*] [{label}] Streaming {len(payload)} bytes into COM2...")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3.0)

    try:
        client.connect((host, port))
        client.sendall(payload)

        resp_buf = bytearray()
        while len(resp_buf) < ctypes.sizeof(SovereignResponseFrame):
            chunk = client.recv(ctypes.sizeof(SovereignResponseFrame) - len(resp_buf))
            if not chunk:
                break
            resp_buf.extend(chunk)

        if len(resp_buf) < ctypes.sizeof(SovereignResponseFrame):
            print(f"[-] Truncated response: expected 40 bytes, got {len(resp_buf)}")
            return None

        resp = SovereignResponseFrame.from_buffer_copy(resp_buf)
        digest = bytes(resp.root_hash).hex()

        print(f"    -> Magic Received : {hex(resp.magic)} ({'SOVA' if resp.magic == SOVA_MAGIC else 'INVALID'})")
        print(f"    -> Status Code    : {hex(resp.status_code)}")
        print(f"    -> Flags Bitmask  : {bin(resp.flags)} (Statutory: {bool(resp.flags & SOVR_FLAG_STATUTORY_DUTY)})")
        print(f"    -> Kernel Digest  : {digest}")
        print(f"    -> Expected SHA   : {expected_hash}")

        return resp
    except Exception as e:
        print(f"[-] Connection failed on {host}:{port}: {e}")
        return None
    finally:
        client.close()

def run_mutation_suite(host=DEFAULT_HOST, port=COM2_PORT):
    print("=== BEGIN SOVEREIGN 40-BYTE STRUCTURED RESPONSE MUTATION SUITE ===")

    # Test 1: Baseline Valid Frame
    f1 = serialize_estate_to_frame()
    r1 = stream_frame_to_com2(f1, host, port, label="Test 1: Authentic Baseline Frame")
    expected_1 = compute_frame_binary_hash(f1)
    assert r1 is not None and r1.magic == SOVA_MAGIC, "Test 1 failed: Bad magic"
    assert r1.status_code == SOVR_STATUS_SUCCESS, f"Test 1 failed: status {hex(r1.status_code)}"
    assert bytes(r1.root_hash).hex() == expected_1, "Test 1 failed: hash mismatch"
    assert r1.flags & SOVR_FLAG_STATUTORY_DUTY, "Test 1 failed: missing statutory duty flag"
    print("[+] PASSED: Valid Frame certified with correct status, flags, and SHA-256 parity.")

    # Test 2: Claimant Mutation
    f2 = serialize_estate_to_frame()
    f2.claimant = b"John B. J. Carroll (Authorized PR)"
    r2 = stream_frame_to_com2(f2, host, port, label="Test 2: Mutated Claimant Field")
    expected_2 = compute_frame_binary_hash(f2)
    assert r2 is not None and r2.status_code == SOVR_STATUS_SUCCESS
    assert bytes(r2.root_hash).hex() == expected_2
    print("[+] PASSED: Field mutation acknowledged with updated cryptographic digest.")

    # Test 3: Lineage Node Expansion
    f3 = serialize_estate_to_frame()
    f3.node_count = 4
    f3.nodes[3].name = b"K'eegwiinjiik Ancestor"
    f3.nodes[3].era_year = 1680
    f3.nodes[3].territorial_hub = b"Black River Watershed"
    f3.nodes[3].title_type = 1
    r3 = stream_frame_to_com2(f3, host, port, label="Test 3: Appended 4th Lineage Node")
    expected_3 = compute_frame_binary_hash(f3)
    assert r3 is not None and r3.status_code == SOVR_STATUS_SUCCESS
    assert bytes(r3.root_hash).hex() == expected_3
    print("[+] PASSED: Expanded node topology verified with root parity.")

    # Test 4: Fault Injection (Corrupt Magic 0xDEADBEEF)
    f4 = serialize_estate_to_frame()
    f4.magic = 0xDEADBEEF
    r4 = stream_frame_to_com2(f4, host, port, label="Test 4: Fault Injection (Invalid Magic)")
    assert r4 is not None and r4.magic == SOVA_MAGIC
    assert r4.status_code == SOVR_STATUS_ERR_MAGIC, f"Test 4 failed: expected ERR_MAGIC, got {hex(r4.status_code)}"
    assert bytes(r4.root_hash) == b"\x00" * 32, "Test 4 failed: expected zeroed hash on error"
    print("[+] PASSED: Microkernel rejected frame with explicit SOVR_STATUS_ERR_MAGIC code.")

    # Test 5: Fault Injection (Node Count Out of Bounds > 8)
    f5 = serialize_estate_to_frame()
    f5.node_count = 12
    r5 = stream_frame_to_com2(f5, host, port, label="Test 5: Fault Injection (Node Count > MAX)")
    assert r5 is not None and r5.magic == SOVA_MAGIC
    assert r5.status_code == SOVR_STATUS_ERR_BOUNDS, f"Test 5 failed: expected ERR_BOUNDS, got {hex(r5.status_code)}"
    assert bytes(r5.root_hash) == b"\x00" * 32, "Test 5 failed: expected zeroed hash on error"
    print("[+] PASSED: Microkernel rejected out-of-bounds node count with SOVR_STATUS_ERR_BOUNDS.")

    print("\n=== ALL 5 STRUCTURED FRAMING PROTOCOL TESTS PASSED ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Structured COM2 framing transport")
    parser.add_argument("mode", choices=["stream-com2", "test-mutations"], help="Execution mode")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=COM2_PORT)
    args = parser.parse_args()

    if args.mode == "stream-com2":
        frame = serialize_estate_to_frame()
        stream_frame_to_com2(frame, args.host, args.port)
    elif args.mode == "test-mutations":
        run_mutation_suite(args.host, args.port)
