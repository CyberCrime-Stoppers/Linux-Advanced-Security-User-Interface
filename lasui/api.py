import asyncio, os, secrets
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.security import APIKeyHeader
from .models import Finding
from .feed import mock_scanner

TOKEN = os.environ.get("LASUI_TOKEN", secrets.token_hex(24))
if not os.environ.get("LASUI_TOKEN"):
    print(f"[dev] ephemeral API token: {TOKEN}")

app = FastAPI(title="LASUI Core", version="0.1.0")

# ---- state -----------------------------------------------------------
queue: asyncio.Queue | None = None       # producer side (scanner)
findings_store: list[Finding] = []       # replay buffer for new clients
clients: set[WebSocket] = set()

auth_header = APIKeyHeader(name="x-lasui-token", auto_error=False)

def require_token(key: str | None = Depends(auth_header)) -> str:
    if not key or not secrets.compare_digest(key, TOKEN):
        raise HTTPException(status_code=401, detail="invalid token")
    return key

# ---- REST ------------------------------------------------------------
@app.get("/api/findings", dependencies=[Depends(require_token)])
async def list_findings():
    return sorted(findings_store, key=lambda f: f.timestamp, reverse=True)

# ---- WebSocket -------------------------------------------------------
@app.websocket("/ws")
async def ws(sock: WebSocket):
    token = sock.query_params.get("token", "")
    if not secrets.compare_digest(token, TOKEN):
        await sock.close(code=4401, reason="unauthorized")
        return

    await sock.accept()
    clients.add(sock)
    try:
        await sock.send_json({"cmd": "snapshot", "findings": [f.model_dump(mode="json") for f in findings_store]})
        # commands may arrive anytime; ignore unknown ones for now
        while True:
            msg = await sock.receive_json()
            if msg.get("cmd") == "ping":
                await sock.send_json({"cmd": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(sock)

# ---- broadcast loop ---------------------------------------------------
async def broadcaster():
    while True:
        finding = await queue.get()
        findings_store.append(finding)
        dead = set()
        payload = {"cmd": "finding", "finding": finding.model_dump(mode="json")}
        for sock in clients:
            try:
                await sock.send_json(payload)
            except Exception:
                dead.add(sock)
        clients -= dead

@app.on_event("startup")
async def startup():
    global queue
    queue = asyncio.Queue(maxsize=1024)
    app.state.queue = queue
    asyncio.create_task(mock_scanner(queue))
    asyncio.create_task(broadcaster())
