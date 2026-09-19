// core/tcp-tunnel.js
import { encrypt } from "./crypto-utils.js";

let nextId = 1;
const clientBuffers = new Map();

const MAX_INIT_BUFFER = 256 * 1024; // 256 Ko max pour le premier buffer
const INIT_TIMEOUT = 30000;         // 30s max d'inactivité

/**
 * Forward TCP brut vers WS/WSS (via Render pour WSS)
 * @param {import('net').Socket} socket      - socket TCP côté serveur local
 * @param {Buffer} firstBuffer               - premier paquet reçu
 * @param {import('ws')} wsTunnel            - connexion WS/WSS (Render passe par un reverse proxy)
 * @param {Map<number, import('net').Socket>} tcpClients - map id -> socket
 */
export function forward(socket, firstBuffer, wsTunnel, tcpClients) {
    const clientId = nextId++;
    tcpClients.set(clientId, socket);

    // Bufferisation du premier paquet pour grouper les débuts de flux verbeux (HTTP/TLS/etc.)
    let totalInitBuffer = firstBuffer.length;
    clientBuffers.set(clientId, firstBuffer);

    // Envoi différé après 50ms (regroupement du "hello")
    const timer = setTimeout(() => {
        const buffered = clientBuffers.get(clientId);
        if (!buffered) return;
        sendEncrypted(wsTunnel, clientId, buffered);
        clientBuffers.delete(clientId);
    }, 50);

    // Timeout anti-idle sur la phase init
    const idleTimeout = setTimeout(() => {
        safeDestroy(socket);
        clientBuffers.delete(clientId);
        tcpClients.delete(clientId);
        clearTimeout(timer);
    }, INIT_TIMEOUT);

    socket.on("data", (chunk) => {
        clearTimeout(idleTimeout); // activité détectée → on annule le timeout init

        if (clientBuffers.has(clientId)) {
            // On est encore en phase "init" (avant l'envoi différé)
            totalInitBuffer += chunk.length;
            if (totalInitBuffer > MAX_INIT_BUFFER) {
                safeDestroy(socket);
                clientBuffers.delete(clientId);
                tcpClients.delete(clientId);
                clearTimeout(timer);
                return;
            }
            clientBuffers.set(clientId, Buffer.concat([clientBuffers.get(clientId), chunk]));
        } else {
            // Flux normal
            sendEncrypted(wsTunnel, clientId, chunk);
        }
    });

    function cleanup() {
        tcpClients.delete(clientId);
        clientBuffers.delete(clientId);
        clearTimeout(timer);
        clearTimeout(idleTimeout);
    }

    socket.on("close", cleanup);
    socket.on("error", cleanup);
}

/**
 * Envoie JSON + base64 (jamais de Buffer binaire) pour compat WS/WSS derrière proxy.
 * Format: { id: number, data: base64( IV(12) + ciphertext + TAG(16) ) }
 */
function sendEncrypted(wsTunnel, clientId, buffer) {
    // Tunnel non prêt → on drop proprement ce paquet
    if (!wsTunnel || wsTunnel.readyState !== 1) return;

    const encrypted = encrypt(buffer); // Buffer = IV(12) + ciphertext + TAG(16)
    const payloadObj = { id: clientId, data: encrypted.toString("base64") };

    try {
        // Toujours en texte (JSON) → AUCUN { binary:true } ici
        wsTunnel.send(JSON.stringify(payloadObj));
    } catch {
        // si l'envoi échoue, on ignore le paquet (socket côté wsServer fera le cleanup au close/error)
    }
}

function safeDestroy(sock) {
    try { sock.destroy(); } catch {}
}
