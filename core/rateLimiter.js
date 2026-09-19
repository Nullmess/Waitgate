import dotenv from 'dotenv';

const RATE_LIMIT_WINDOW_MS   = Number(process.env.RL_WINDOW_MS || 60_000);     // 1 min
const RATE_LIMIT_MAX         = Number(process.env.RL_MAX || 100);              // max 100 requêtes/min par IP
const BAN_DURATION_MS        = Number(process.env.RL_BAN_MS || 300_000);       // ban 5 min
const GLOBAL_BAN_THRESHOLD   = Number(process.env.RL_GLOBAL_THRESHOLD || 100); // seuil d'IPs bannies pour ban global
const GLOBAL_BAN_DURATION_MS = Number(process.env.RL_GLOBAL_BAN_MS || 60_000); // 1 min ban global

const _log = console.log;
const ipRequests = new Map();

console.log = _log;
console.log = function (...args) {
  if (
    typeof args[0] === "string" &&
    args[0].startsWith("[dotenv@")
  ) return;
  _log.apply(console, args);
};
dotenv.config();

let globalBanActive = false;
let globalBanTimeout = null;

// Récup Whitelist d'IP via .env (statique)
const whitelist = process.env.WHITELIST_IPS ? process.env.WHITELIST_IPS.split(',') : [];
// Whitelist dynamique (en mémoire)
const dynamicWhitelist = new Set();

/**
 * Ajoute une IP à la whitelist dynamique (ne pas bannir ni limiter)
 * @param {string} ip
 */
export function addDynamicWhitelist(ip) {
    if (ip && !dynamicWhitelist.has(ip)) dynamicWhitelist.add(ip);
}

/**
 * Vérif IP appartient à la whitelist (statique OU dynamique).
 * @param {string} ip
 * @returns {boolean}
 */
function isWhitelisted(ip) {
    return whitelist.includes(ip) || dynamicWhitelist.has(ip);
}

/**
 * Récup l'IP d'une requête HTTP ou d'un socket.
 * Prend "x-forwarded-for" si présent.
 * @param {Object} reqOrSocket
 * @returns {string}
 */
export function getIp(reqOrSocket) {
    let ip = reqOrSocket.headers?.["x-forwarded-for"];
    if (ip && ip.includes(",")) ip = ip.split(",")[0].trim();
    return ip
        || reqOrSocket.socket?.remoteAddress
        || reqOrSocket.remoteAddress
        || "";
}

/**
 * Vérif rate limit pour IP.
 * Active ban tmp si dépassement.
 * @param {string} ip
 * @returns {boolean} true si autorisé / false si bloqué
 */
export function checkRateLimit(ip) {
    if (isWhitelisted(ip)) return true; // Whitelist : jamais bloquée
    if (globalBanActive) return false; // Ban global : bloque tout sauf whitelist (déjà exclue)
    if (!ip) return true; // pas d'IP = pas de blocage
    let data = ipRequests.get(ip);
    const now = Date.now();
    if (!data) {
        data = { count: 1, start: now, bannedUntil: 0 };
        ipRequests.set(ip, data);
        return true;
    }
    if (data.bannedUntil && now < data.bannedUntil) {
        // IP encore bannie
        return false;
    }
    if (now - data.start > RATE_LIMIT_WINDOW_MS) {
        // Nouvelle fenêtre, reset compteur
        data.start = now;
        data.count = 1;
        data.bannedUntil = 0;
        return true;
    }
    data.count++;
    if (data.count > RATE_LIMIT_MAX) {
        data.bannedUntil = now + BAN_DURATION_MS;
        console.log(`[INFO] IP ${ip} banned until ${new Date(data.bannedUntil).toISOString()}`);
        return false;
    }
    return true;
}

/**
 * Vérif nb d'IPs bannies dépasse seuil pour activer ban global.
 * Active/désactive ban global auto.
 */
export function checkGlobalBan() {
    const now = Date.now();
    let bannedCount = 0;
    for (const data of ipRequests.values()) {
        if (data.bannedUntil && data.bannedUntil > now) bannedCount++;
    }
    if (!globalBanActive && bannedCount > GLOBAL_BAN_THRESHOLD) {
        console.warn(`⚠️ Mode BAN GLOBAL activé : ${bannedCount} IPs bannies`);
        globalBanActive = true;

        if (globalBanTimeout) clearTimeout(globalBanTimeout);
        globalBanTimeout = setTimeout(() => {
            globalBanActive = false;
            console.log("✅ Mode BAN GLOBAL désactivé");
        }, GLOBAL_BAN_DURATION_MS);
    }
}

/**
 * Purge IPs inactives pour pas mémoire inutile.
 * À appeler périodiquement.
 */
export function purgeOldIPs() {
    const now = Date.now();
    for (const [ip, data] of ipRequests.entries()) {
        if (now - data.start > 20 * RATE_LIMIT_WINDOW_MS && (!data.bannedUntil || now > data.bannedUntil)) {
            ipRequests.delete(ip);
        }
    }
}

// Nettoyage auto toutes les 10 min
setInterval(purgeOldIPs, 10 * 60 * 1000);
