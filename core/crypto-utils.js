// core/crypto-utils.js
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { TUNNEL_CHACHA_KEY } from "../config.js";
import crypto from "crypto";

const KEY = Buffer.from(TUNNEL_CHACHA_KEY, "hex");
const NONCE_LENGTH = 12;

export function encrypt(plainBuf) {
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const chacha = new ChaCha20Poly1305(KEY);
    const ciphertextAndTag = chacha.seal(nonce, Buffer.from(plainBuf));
    return Buffer.concat([nonce, Buffer.from(ciphertextAndTag)]);
}

export function decrypt(payloadBuf) {
    const nonce = payloadBuf.slice(0, NONCE_LENGTH);
    const ciphertextAndTag = payloadBuf.slice(NONCE_LENGTH);
    const chacha = new ChaCha20Poly1305(KEY);
    const plain = chacha.open(nonce, Buffer.from(ciphertextAndTag));
    if (!plain) throw new Error("ChaCha20-Poly1305: Authentication failed (bad key, nonce or data)");
    return Buffer.from(plain);
}

export function encryptForDownload(plainBuf, base64Key) {
    const key = Buffer.from(base64Key, "base64");
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const chacha = new ChaCha20Poly1305(key);
    const encrypted = chacha.seal(nonce, Buffer.from(plainBuf));
    return Buffer.concat([nonce, Buffer.from(encrypted)]);
}
