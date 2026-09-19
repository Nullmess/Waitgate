// core/exposer-ip.js
import fs from "fs";
import path from "path";

const ENV_PATH = path.resolve(process.cwd(), ".env");

export function setExposerIpEnv(ip) {
    if (!ip) return;
    let env = fs.readFileSync(ENV_PATH, "utf-8").split("\n");
    let found = false;
    env = env.map(line => {
        if (line.startsWith("EXPOSER_IP=")) {
            found = true;
            return `EXPOSER_IP=${ip}`;
        }
        return line;
    });
    if (!found) env.push(`EXPOSER_IP=${ip}`);
    fs.writeFileSync(ENV_PATH, env.join("\n"));
}

export function clearExposerIpEnv() {
    if (!fs.existsSync(ENV_PATH)) return;
    let env = fs.readFileSync(ENV_PATH, "utf-8").split("\n");
    env = env.map(line =>
        line.startsWith("EXPOSER_IP=") ? "EXPOSER_IP=" : line
    );
    fs.writeFileSync(ENV_PATH, env.join("\n"));
}
