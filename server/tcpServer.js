// server/tcpServer.js
import net from "net";
import { getIp, checkRateLimit } from "../core/rateLimiter.js";
import * as tcpTunnel from "../core/tcp-tunnel.js";

export function createTcpServer(httpServer, wsTunnelRef, tcpClients) {
  return net.createServer((socket) => {
    const ip = getIp(socket);
    if (!checkRateLimit(ip)) {
      socket.destroy();
      return;
    }

    socket.once("data", (buffer) => {
      const str = buffer.toString();
      // Si requête HTTP -> passer SRV HTTP
      if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS) /.test(str)) {
        socket.unshift(buffer);
        httpServer.emit("connection", socket);
      }
      // Sinon si tunnel WS ouvert ->forwarder tcpTunnel
      else if (wsTunnelRef.wsTunnel && wsTunnelRef.wsTunnel.readyState === 1) {
        tcpTunnel.forward(socket, buffer, wsTunnelRef.wsTunnel, tcpClients);
      }
      else {
        socket.destroy();
      }
    });
  });
}
