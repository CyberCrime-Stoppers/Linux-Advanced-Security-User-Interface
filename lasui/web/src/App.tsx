const ws = new WebSocket(`wss://${location.host}/ws`);

ws.onmessage = (ev) => {
  const finding = JSON.parse(ev.data);
  store.addFinding(finding);   // severity-tagged, sortable
};

function triggerScan(target: string) {
  ws.send(JSON.stringify({ cmd: "audit", host: target }));
}
