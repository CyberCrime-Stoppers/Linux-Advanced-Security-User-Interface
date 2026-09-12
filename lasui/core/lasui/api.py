from fastapi import FastAPI, WebSocket
import asyncio, json

app = FastAPI(title="LASUI")

@app.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept()
    while True:
        msg = json.loads(await sock.receive_text())
        if msg["cmd"] == "audit":
            # fan out to Perl agents, stream results back
            async for line in run_agent(msg.get("host", "localhost")):
                await sock.send_text(line)

async def run_agent(host: str):
    proc = await asyncio.create_subprocess_exec(
        "perl", "agents/perl/bin/lasui-audit",
        stdout=asyncio.subprocess.PIPE)
    async for line in proc.stdout:
        yield line.decode()
