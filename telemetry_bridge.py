#!/usr/bin/env python3
import asyncio
import json
import logging
import math
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [BRIDGE]: %(message)s"
)

SOURCE_WS = "ws://127.0.0.1:8765"
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 8000
PATH_STREAM = "/v1/telemetry/stream"
TARGET_CADENCE_HZ = 79.000000

try:
    import websockets
except ImportError:
    logging.error("Missing websockets library")
    sys.exit(1)

class TelemetryBridgeServer:
    def __init__(self, target_hz: float = TARGET_CADENCE_HZ):
        self.target_hz = target_hz
        self.target_interval_sec = 1.0 / target_hz
        self.seq = 0
        self.last_ts = None
        self.subscribers = {}
        self.latest_sample = None

    def _normalize_stability(self, lyapunov_exp: float) -> float:
        if lyapunov_exp <= -10.0:
            return 1.0
        if lyapunov_exp >= 0.0:
            return 0.0
        return round(1.0 / (1.0 + math.exp((lyapunov_exp + 5.0))), 6)

    def _calculate_drift_ppm(self, delta_t: float) -> float:
        if delta_t <= 0.0:
            return 0.0
        measured_hz = 1.0 / delta_t
        drift_ppm = ((measured_hz - self.target_hz) / self.target_hz) * 1e6
        return round(drift_ppm, 4)

    def transform_frame(self, raw_json: str) -> dict | None:
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError:
            return None

        if payload.get("type") != "MANIFOLD_NDC_STREAM":
            return None

        now = payload.get("timestamp", time.time())
        delta_t = (now - self.last_ts) if self.last_ts else self.target_interval_sec
        self.last_ts = now
        self.seq += 1

        stability_data = payload.get("stability", {})
        lyap = float(stability_data.get("lyapunov", 0.0))
        s_index = self._normalize_stability(lyap)
        drift_ppm = self._calculate_drift_ppm(delta_t)

        return {
            "event": "metric_sample",
            "seq": self.seq,
            "timestamp": now,
            "metrics": {
                "stability_index": s_index,
                "drift_ppm": drift_ppm,
                "delta_t": round(delta_t, 6),
                "carrier_hz": round(1.0 / delta_t if delta_t > 0 else 0.0, 4)
            },
            "raw_coordinates": {
                "vector_ndc": payload.get("vector", [0.0, 0.0]),
                "p3d": payload.get("p3d", [0.0, 0.0, 0.0]),
                "phase_x": stability_data.get("phase_x", 0.0),
                "phase_y": stability_data.get("phase_y", 0.0)
            }
        }

    async def register_subscriber(self, ws):
        # In websockets >= 14 (Python 3.14), handler receives (websocket) only
        path = getattr(ws, "path", getattr(ws.request, "path", PATH_STREAM))
        if path != PATH_STREAM:
            await ws.close(1008, "Invalid subscription path")
            return

        logging.info(f"Consumer connected to {PATH_STREAM}")
        sub_info = {"sample_rate_hz": 10, "last_sent": 0.0}
        self.subscribers[ws] = sub_info

        try:
            async for raw in ws:
                try:
                    cmd = json.loads(raw)
                    if cmd.get("action") == "subscribe":
                        rate = int(cmd.get("sample_rate_hz", 10))
                        sub_info["sample_rate_hz"] = max(1, min(rate, 100))
                        logging.info(f"Updated client rate to {sub_info['sample_rate_hz']} Hz")
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        finally:
            self.subscribers.pop(ws, None)
            logging.info("Consumer disconnected.")

    async def dispatch_loop(self):
        while True:
            await asyncio.sleep(0.005)
            if not self.subscribers or not self.latest_sample:
                continue

            now = time.time()
            payload_str = json.dumps(self.latest_sample)
            coros = []

            for ws, config in list(self.subscribers.items()):
                interval = 1.0 / config["sample_rate_hz"]
                if (now - config["last_sent"]) >= interval:
                    config["last_sent"] = now
                    coros.append(ws.send(payload_str))

            if coros:
                await asyncio.gather(*coros, return_exceptions=True)

    async def ingest_source(self):
        while True:
            try:
                logging.info(f"Connecting upstream to {SOURCE_WS}...")
                async with websockets.connect(SOURCE_WS) as ws:
                    logging.info("Connected to Tordial-GS MeshBroadcaster.")
                    async for raw_msg in ws:
                        transformed = self.transform_frame(raw_msg)
                        if transformed:
                            self.latest_sample = transformed
            except Exception as e:
                logging.warning(f"Upstream disconnect ({e}). Retrying in 2.0s...")
                await asyncio.sleep(2.0)

async def main():
    bridge = TelemetryBridgeServer()
    server = await websockets.serve(
        bridge.register_subscriber,
        BRIDGE_HOST,
        BRIDGE_PORT,
        reuse_port=True
    )
    logging.info(f"Bridge gateway listening on ws://{BRIDGE_HOST}:{BRIDGE_PORT}{PATH_STREAM}")
    await asyncio.gather(
        bridge.ingest_source(),
        bridge.dispatch_loop(),
        server.wait_closed()
    )

if __name__ == "__main__":
    asyncio.run(main())
