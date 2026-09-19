// server.js
import { createHttpServer } from "./server/httpServer.js";
import { createTcpServer } from "./server/tcpServer.js";
import { createWsServer } from "./server/wsServer.js";
import * as wsHandler from "./core/ws-handler.js";
import dotenv from "dotenv";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "url";
import path from "path";

// Decla __filename & __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Chargement .env
dotenv.config();

// Declaration des variables
const tcpClients = new Map();
const wsTunnelRef = { wsTunnel: null };
const ctx = { exposerIp: null, wsTunnel: null, tcpClients };
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;

// SRV HTTP & TCP & WS
const wss = new WebSocketServer({ noServer: true });
const httpServer = createHttpServer(wsTunnelRef, tcpClients, ctx);
const tcpServer = createTcpServer(httpServer, wsTunnelRef, tcpClients, ctx);
const setupWsUpgrade = createWsServer(process.env.TUNNEL_TOKEN, wss, wsTunnelRef, tcpClients, wsHandler, ctx);

// Patch log anti-dotenv
const _log = console.log;
console.log = function (...args) {
  if (
    typeof args[0] === "string" &&
    args[0].startsWith("[dotenv@")
  ) return;
  _log.apply(console, args);
};
console.log = _log;

// Branche tunnel WS sur SRV HTTP
setupWsUpgrade(httpServer);

// Lancement du SRV TCP
tcpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`[INFO] Server listens on port ${PORT}`);
  console.log("[INFO] Waiting for a WS tunnel client on /tunnel...");
});
