import socket
import json
import sys
import argparse
from jump_chain import estate

DEFAULT_PORT = 9999
DEFAULT_HOST = "127.0.0.1"

def run_server(host=DEFAULT_HOST, port=DEFAULT_PORT):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[teleport-server] Listening on {host}:{port}...")

    try:
        while True:
            conn, addr = server.accept()
            print(f"[teleport-server] Connection accepted from {addr}")
            
            # Generate deterministic payload
            result = estate.evaluate_jurisdictional_conflict(
                corporate_entity="Doyon / Regional Corporate Ledger"
            )
            payload = json.dumps(result, indent=4).encode("utf-8")
            
            conn.sendall(payload)
            conn.close()
    except KeyboardInterrupt:
        print("\n[teleport-server] Server stopped.")
    finally:
        server.close()

def query_client(host=DEFAULT_HOST, port=DEFAULT_PORT):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((host, port))
        raw_data = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            raw_data += chunk
        
        parsed = json.loads(raw_data.decode("utf-8"))
        print("[teleport-client] Received evaluated payload:")
        print(json.dumps(parsed, indent=4))
    except ConnectionRefusedError:
        print(f"[teleport-client] Connection failed. Is the server running on {host}:{port}?")
    finally:
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Teleport socket JSON holder")
    parser.add_argument("mode", choices=["server", "client"], help="Run as server or client")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port number (default: {DEFAULT_PORT})")
    
    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.host, args.port)
    else:
        query_client(args.host, args.port)
