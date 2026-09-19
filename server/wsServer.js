// server/wsServer.js
import { getIp, checkRateLimit, addDynamicWhitelist } from "../core/rateLimiter.js";
import { setExposerIpEnv, clearExposerIpEnv } from "../core/exposer-ip.js";

/**
 * Crée le serveur WS (WS local ou WSS via reverse proxy type Render)
 * @param {string} TUNNEL_TOKEN
 * @param {WebSocketServer} wss
 * @param {object} wsTunnelRef
 * @param {Map} tcpClients
 * @param {object} wsHandler
 * @param {object} ctx
 */
export function createWsServer(TUNNEL_TOKEN, wss, wsTunnelRef, tcpClients, wsHandler, ctx) {
    // Vide l'IP exposée au démarrage
    clearExposerIpEnv();

    wss.on("connection", (ws, req) => {
        // Mode texte partout (JSON + base64)
        ws.binaryType = "arraybuffer";

        wsTunnelRef.wsTunnel = ws;
        ctx.wsTunnel = ws;

        // Gère la connexion WS côté tunnel (JSON-only)
        wsHandler.handle(ws, tcpClients);

        // whitelist dynamique
        const ip = getIp(req);
        addDynamicWhitelist(ip);

        // Reset l'IP exposée
        ctx.exposerIp = null;

        // Attend handshake HELLO pour exposer IP WAN
        ws.on("message", function handleHello(msg) {
            try {
                const str = Buffer.isBuffer(msg) ? msg.toString() : (typeof msg === "string" ? msg : "");
                const obj = JSON.parse(str);
                if (obj && obj.type === "HELLO" && obj.ip) {
                    ctx.exposerIp = obj.ip;
                    setExposerIpEnv(obj.ip);
                    ws.off("message", handleHello);
                }
            } catch {
                // Pas un message HELLO → ignore
            }
        });

        const cleanup = () => {
            wsTunnelRef.wsTunnel = null;
            ctx.wsTunnel = null;
            ctx.exposerIp = null;
            clearExposerIpEnv();
            for (const sock of tcpClients.values()) sock.destroy();
            tcpClients.clear();
        };

        ws.on("close", cleanup);
        ws.on("error", cleanup);
    });

    return (httpServer) => {
        httpServer.on("upgrade", (req, socket, head) => {
            const ip = getIp(req);
            if (!checkRateLimit(ip)) {
                socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
                socket.destroy();
                return;
            }

            if (req.url.startsWith("/tunnel")) {
                const authHeader = req.headers["authorization"];
                if (!authHeader || !authHeader.startsWith("Bearer ")) {
                    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
                    socket.destroy();
                    return;
                }

                const token = authHeader.slice(7);
                if (token !== TUNNEL_TOKEN) {
                    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
                    socket.destroy();
                    return;
                }

                // Un seul tunnel à la fois
                if (wsTunnelRef.wsTunnel && wsTunnelRef.wsTunnel.readyState === 1) {
                    socket.destroy();
                    return;
                }

                wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
            } else {
                socket.destroy();
            }
        });
    };
}
