import asyncio
import json
import websockets

async def check():
    try:
        async with websockets.connect("ws://127.0.0.1:8000/v1/telemetry/stream") as ws:
            await ws.send(json.dumps({"action": "subscribe", "sample_rate_hz": 10}))
            msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
            data = json.loads(msg)
            print(f"Frame received: Seq={data['seq']} Event={data['event']} Metrics={data['metrics']}")
    except asyncio.TimeoutError:
        print("Timeout: No telemetry frames arriving from upstream (Tordial-GS port 8765 idle)")

asyncio.run(check())
