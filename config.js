// config.js
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ENV_PATH = path.resolve(__dirname, ".env");

// Charge .env en objet
function loadEnv() {
    if (!fs.existsSync(ENV_PATH)) return {};
    return Object.fromEntries(
        fs
            .readFileSync(ENV_PATH, "utf-8")
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l && !l.startsWith("#"))
            .map((l) => l.split("="))
            .map(([k, ...v]) => [k.trim(), v.join("=").trim()])
    );
}

// Save l'objet .env
function saveEnv(env) {
    fs.writeFileSync(
        ENV_PATH,
        Object.entries(env)
            .map(([k, v]) => `${k}=${v}`)
            .join("\n")
    );
}

let env = loadEnv();

// TUNNEL_CHACHA_KEY
if (!env.TUNNEL_CHACHA_KEY || !/^[0-9a-f]{64}$/i.test(env.TUNNEL_CHACHA_KEY)) {
    env.TUNNEL_CHACHA_KEY = crypto.randomBytes(32).toString("hex");
}
// TUNNEL_TOKEN
if (!env.TUNNEL_TOKEN || !/^wgt_[a-f0-9]{48}$/i.test(env.TUNNEL_TOKEN)) {
    env.TUNNEL_TOKEN = "wgt_" + crypto.randomBytes(24).toString("hex");
}
// DASH_USER
if (!env.DASH_USER) {
    env.DASH_USER = "admin";
}
// DASH_PASS
if (!env.DASH_PASS) {
    env.DASH_PASS = crypto.randomBytes(12).toString("base64");
}
// LOGIN_SECRET
if (!env.LOGIN_SECRET || !/^[0-9a-f]{64}$/i.test(env.LOGIN_SECRET)) {
    env.LOGIN_SECRET = crypto.randomBytes(32).toString("hex");
}
// TOTP_ENABLED
if (!env.TOTP_ENABLED) {
    env.TOTP_ENABLED = "false";
}
// TOTP_SECRET
if (!env.TOTP_SECRET) {
    env.TOTP_SECRET = "";
}
// WHITELIST_IPS
if (!env.WHITELIST_IPS) {
    env.WHITELIST_IPS = "127.0.0.1,192.168.1.0/24";
}
// EXPOSER_IP
if (env.EXPOSER_IP === undefined) {
    env.EXPOSER_IP = "";
}

// Anti-DDoS defaults
if (!env.RL_WINDOW_MS) env.RL_WINDOW_MS = "60000";
if (!env.RL_MAX) env.RL_MAX = "80";
if (!env.RL_BAN_MS) env.RL_BAN_MS = "300000";
if (!env.RL_GLOBAL_THRESHOLD) env.RL_GLOBAL_THRESHOLD = "200";
if (!env.RL_GLOBAL_BAN_MS) env.RL_GLOBAL_BAN_MS = "60000";
if (!env.HTTP_IDLE_TIMEOUT_MS) env.HTTP_IDLE_TIMEOUT_MS = "15000";

saveEnv(env);

// Info option
console.log("[INFO] DASH_USER     =", env.DASH_USER);
console.log("[INFO] DASH_PASS     =", env.DASH_PASS);
console.log("[INFO] TUNNEL_TOKEN  =", env.TUNNEL_TOKEN);
console.log("[INFO] TOTP_SECRET   =", env.TOTP_SECRET);

// Exporte les valeurs
export const TUNNEL_CHACHA_KEY = env.TUNNEL_CHACHA_KEY.trim();
export const TUNNEL_TOKEN = env.TUNNEL_TOKEN.trim();
export const LOGIN_SECRET = env.LOGIN_SECRET.trim();
export const DASH_USER = env.DASH_USER.trim();
export const DASH_PASS = env.DASH_PASS.trim();
export const TOTP_ENABLED = false;
export const TOTP_SECRET = "";
export const WHITELIST_IPS = env.WHITELIST_IPS.trim();
