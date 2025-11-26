import { WebSocketServer } from "ws";
export function createWsServer(httpServer) {
  const wss = new WebSocketServer({ noServer: true });
  httpServer.on("upgrade", (req, socket, head) => {
    if (req.url === "/ws") wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
    else socket.destroy();
  });
  const broadcast = (msg) => {
    const s = typeof msg === "string" ? msg : JSON.stringify(msg);
    wss.clients.forEach((c) => { if (c.readyState === 1) c.send(s); });
  };
  return { wss, broadcast };
}
