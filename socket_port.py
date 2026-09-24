import socket
import json
import sys
import argparse
import io
import contextlib
import copy

with contextlib.redirect_stdout(io.StringIO()):
    from jump_chain import estate, TitleStatus
    from audit_contract import serialize_estate_to_frame, compute_frame_binary_hash, SovereignAuditFrame, CLineageNode

DEFAULT_PORT = 9999
DEFAULT_HOST = "127.0.0.1"
COM2_PORT = 9998

def run_server(host=DEFAULT_HOST, port=DEFAULT_PORT):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[teleport-server] Listening on {host}:{port} (Dual JSON + 808-byte Binary mode)...")

    try:
        while True:
            conn, addr = server.accept()
            data = conn.recv(64).decode("utf-8", errors="ignore").strip()
            
            if "GET_BIN_FRAME" in data:
                frame = serialize_estate_to_frame()
                payload = bytes(frame)
                conn.sendall(payload)
                digest = compute_frame_binary_hash(frame)
                print(f"[teleport-server] Sent 808-byte SovereignAuditFrame to {addr} (SHA-256: {digest[:16]}...)")
            else:
                result = estate.evaluate_jurisdictional_conflict(
                    corporate_entity="Doyon / Regional Corporate Ledger"
                )
                payload = json.dumps(result, indent=4).encode("utf-8")
                conn.sendall(payload)
                print(f"[teleport-server] Sent JSON evaluation payload to {addr}")
            
            conn.close()
    except KeyboardInterrupt:
        print("\n[teleport-server] Shutting down.")
    finally:
        server.close()

def query_client(host=DEFAULT_HOST, port=DEFAULT_PORT, binary_mode=False):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((host, port))
        
        if binary_mode:
            client.sendall(b"GET_BIN_FRAME\n")
            raw_data = bytearray()
            while len(raw_data) < 808:
                chunk = client.recv(808 - len(raw_data))
                if not chunk:
                    break
                raw_data.extend(chunk)
            
            if len(raw_data) == 808:
                frame = SovereignAuditFrame.from_buffer_copy(raw_data)
                digest = compute_frame_binary_hash(frame)
                print(f"[teleport-client] Successfully received 808-byte frame from {host}:{port}")
                print(f"      -> Magic: 0x{frame.magic:08X} ({'VALID' if frame.magic == 0x534F5652 else 'INVALID'})")
                print(f"      -> Role Badge: 0x{frame.fiduciary_role:04X}")
                print(f"      -> Claimant: {frame.claimant.decode('utf-8', errors='replace')}")
                print(f"      -> Active Lineage Nodes: {frame.node_count}")
                print(f"      -> Cryptographic Digest: {digest}")
                assert digest == "de154802cd1da19a38624c54ab004bfb95658243feb72d41b270563e8cb5daea"
                print(f"[teleport-client] *** BINARY DIGEST MATCHES KERNEL SEED! ***")
            else:
                print(f"[teleport-client] Incomplete payload: got {len(raw_data)}/808 bytes")
        else:
            client.sendall(b"GET_JSON\n")
            chunks = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            raw_data = b"".join(chunks)
            parsed = json.loads(raw_data.decode("utf-8"))
            print("[teleport-client] Received evaluated JSON payload:")
            print(json.dumps(parsed, indent=4))
            
    except ConnectionRefusedError:
        print(f"[teleport-client] Connection failed on {host}:{port}")
    finally:
        client.close()

def stream_frame_to_com2(frame: SovereignAuditFrame, host=DEFAULT_HOST, port=COM2_PORT, label="Standard Frame"):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((host, port))
        payload = bytes(frame)
        expected_digest = compute_frame_binary_hash(frame)
        
        print(f"[*] [{label}] Streaming {len(payload)} bytes into COM2...")
        client.sendall(payload)
        
        ack_digest = bytearray()
        while len(ack_digest) < 32:
            chunk = client.recv(32 - len(ack_digest))
            if not chunk:
                break
            ack_digest.extend(chunk)
            
        ack_hex = ack_digest.hex()
        print(f"    -> Expected SHA-256 : {expected_digest}")
        print(f"    -> Kernel Returned  : {ack_hex}")
        
        if frame.magic != 0x534F5652:
            if ack_hex == "00" * 32:
                print(f"    [+] PASSED: Microkernel rejected invalid magic with zeroed vector.")
            else:
                print(f"    [-] FAILED: Microkernel did not reject invalid magic.")
        elif ack_hex == expected_digest:
            print(f"    [+] PASSED: 1:1 Live Cryptographic Parity Confirmed.")
        else:
            print(f"    [-] FAILED: Digest mismatch!")
            
    except ConnectionRefusedError:
        print(f"[-] Connection failed. Is QEMU running with COM2 on {host}:{port}?")
    finally:
        client.close()

def run_mutation_suite(host=DEFAULT_HOST, port=COM2_PORT):
    print("=== BEGIN SOVEREIGN AUDIT FRAME MUTATION SUITE ===")
    
    # Test 1: Authentic standard frame
    frame1 = serialize_estate_to_frame()
    stream_frame_to_com2(frame1, host, port, label="Test 1: Authentic Baseline Frame")
    
    # Test 2: Mutate claimant string
    frame2 = serialize_estate_to_frame()
    frame2.claimant = b"John B. J. Carroll (Authorized PR)"
    stream_frame_to_com2(frame2, host, port, label="Test 2: Mutated Claimant Field")
    
    # Test 3: Add an additional lineage node
    frame3 = serialize_estate_to_frame()
    frame3.node_count = 4
    frame3.nodes[3].name = b"K'eegwiinjiik Ancestor"
    frame3.nodes[3].era_year = 1680
    frame3.nodes[3].territorial_hub = b"Black River Watershed"
    frame3.nodes[3].title_type = 1
    stream_frame_to_com2(frame3, host, port, label="Test 3: Appended 4th Lineage Node")
    
    # Test 4: Fault injection - corrupt magic
    frame4 = serialize_estate_to_frame()
    frame4.magic = 0xDEADBEEF
    stream_frame_to_com2(frame4, host, port, label="Test 4: Fault Injection (Corrupt Magic 0xDEADBEEF)")
    
    print("=== MUTATION SUITE COMPLETE ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Teleport socket JSON/Binary/COM2 transport")
    parser.add_argument("mode", choices=["server", "client", "stream-com2", "test-mutations"], help="Operation mode")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--bin", action="store_true", help="Request raw binary audit contract frame")

    args = parser.parse_args()
    if args.mode == "server":
        port = args.port or DEFAULT_PORT
        run_server(args.host, port)
    elif args.mode == "client":
        port = args.port or DEFAULT_PORT
        query_client(args.host, port, binary_mode=args.bin)
    elif args.mode == "stream-com2":
        port = args.port or COM2_PORT
        frame = serialize_estate_to_frame()
        stream_frame_to_com2(frame, args.host, port)
    elif args.mode == "test-mutations":
        port = args.port or COM2_PORT
        run_mutation_suite(args.host, port)
