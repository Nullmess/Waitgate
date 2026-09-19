// server/httpServer.js
import http from "http";
import fs from "fs";
import path from "path";
import * as dashboard from "../routes/dashboard.js";
import { getIp, checkRateLimit } from "../core/rateLimiter.js";

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 Mo
const indexPath = path.join(process.cwd(), "views", "index.html");

export function createHttpServer(wsTunnelRef, tcpClients) {
  return http.createServer((req, res) => {
    const SOCKET_TIMEOUT_MS = Number(process.env.HTTP_IDLE_TIMEOUT_MS || 15000);
    if (!req.socket._waitgate_timeout_installed) {
    req.socket._waitgate_timeout_installed = true;
    req.socket.on("timeout", function () {
        try {
        this.destroy();
        } catch (_) {}
    });
    }
    req.socket.setTimeout(SOCKET_TIMEOUT_MS);

    const ip = getIp(req);
    if (!checkRateLimit(ip)) {
        res.writeHead(429, {
            "Content-Type": "text/plain",
            "Retry-After": "60",
            "X-RateLimit-Limit": String(process.env.RL_MAX || 100),
            "X-RateLimit-Window-MS": String(process.env.RL_WINDOW_MS || 60000)
        });
        return res.end("Too many requests, try again later.\n");
    }

    const WAITGATE_API_ROUTES = [
        "/api/login",
        "/api/logout",
        "/api/tfa-setup",
        "/api/tfa-test",
        "/api/status",
        "/api/wait-tunnel"
    ];

    // Routes Dashboard & API Waitgate seulement
    if (
        req.url === "/dashboard" ||
        req.url === "/download" ||
        WAITGATE_API_ROUTES.includes(req.url)
    ) {
        dashboard.handle(req, res, { wsTunnel: wsTunnelRef.wsTunnel, tcpClients });
        return;
    }

    // Accueil / si pas de tunnel WS ouvert
    if (!wsTunnelRef.wsTunnel || wsTunnelRef.wsTunnel.readyState !== 1) {
      if (fs.existsSync(indexPath)) {
        const html = fs.readFileSync(indexPath);
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end(html);
      } else {
        res.writeHead(502);
        return res.end("Aucun client proxy connecté.");
      }
    }

    // Proxy HTTP via tunnel WS
    const bodyChunks = [];
    let bodySize = 0;
    let aborted = false;

    req.on("data", (chunk) => {
      if (aborted) return;
      bodySize += chunk.length;
      if (bodySize > MAX_BODY_SIZE) {
        aborted = true;
        res.writeHead(413);
        res.end("Payload Too Large");
        req.destroy();
        return;
      }
      bodyChunks.push(chunk);
    });

    req.on("end", () => {
      if (aborted) return;
      const toProxy = {
        method: req.method,
        path: req.url,
        headers: req.headers,
        body: bodyChunks.length ? Buffer.concat(bodyChunks).toString("base64") : undefined,
      };
      const reqId = Math.random().toString(36).slice(2);

      const onMessage = (msg) => {
        try {
          const data = JSON.parse(msg);
          if (data.reqId !== reqId) return;
          wsTunnelRef.wsTunnel.off("message", onMessage);
          res.writeHead(data.status || 200, data.headers || {});
          res.end(data.body ? Buffer.from(data.body, "base64") : undefined);
        } catch {
          // ignore JSON parse errors
        }
      };

      wsTunnelRef.wsTunnel.on("message", onMessage);
      wsTunnelRef.wsTunnel.send(JSON.stringify({ type: "http-proxy", reqId, req: toProxy }));
    });
  });
}
