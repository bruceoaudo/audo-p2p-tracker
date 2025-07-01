//=============================================//
// AUTHOR: BRUCE ODOYO AUDO
// LICENSE: MIT
//=============================================//
// FILE: app.js
// DESCRIPTION: Geographically distributed TCP peer bootstrap server.
//              Handles client registration, deregistration, heartbeat, and peer discovery.
//              Includes DoS protection, IP rate limiting, Geo lookup, and log rotation.
//=============================================//
// CREATION DATE: 28th June 2025
// LAST UPDATED: [Keep updating this with every major change]
//=============================================//
// DEPENDENCIES:
// - Node.js (>=v18)
// - dotenv
// - axios
// - fs, path, net (Node core modules)
// - ./db/saveLogsToDB.js (Custom DB log offloader)
//=============================================//
// USAGE:
// 1. Configure .env with SERVER_PORT and DB settings.
// 2. Run: node server.js
// 3. Use client to send JSON actions: "register", "unregister", "heartbeat".
//=============================================//
// NOTES:
// - Uses GeoDNS load balancing across multiple global VPS servers.
// - Status codes are defined in STATUS_CODES for client interpretation.
// - Logs rotate and get offloaded to a database.
//=============================================//

//=============================================//
// Module Imports
//=============================================//
import dotenv from "dotenv";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import axios from "axios"; // For IP geolocation lookup
import { saveLogsToDB } from "./db/saveLogsToDB.js"; // DB module for log offloading

dotenv.config();

//=============================================//
// Status and Error Codes
//=============================================//
const STATUS_CODES = {
  SUCCESS_REGISTER: { code: 1000, message: "Registration successful" },
  SUCCESS_UNREGISTER: { code: 1001, message: "Unregistered successfully" },
  SUCCESS_HEARTBEAT: { code: 1002, message: "Heartbeat acknowledged" },
  ERROR_UNKNOWN_ACTION: { code: 2000, message: "Unknown action" },
  ERROR_INVALID_JSON: { code: 2001, message: "Invalid JSON" },
  ERROR_RATE_LIMIT: { code: 2002, message: "Too many requests, slow down." },
  ERROR_GLOBAL_DOS: { code: 2003, message: "Global rate limit exceeded" },
  ERROR_PAYLOAD_TOO_LARGE: { code: 2004, message: "Payload too large" },
  ERROR_IDLE_TIMEOUT: { code: 2005, message: "Idle timeout" },
  ERROR_GEO_LOOKUP_FAILED: { code: 2006, message: "Geolocation lookup failed" },
};

//=============================================//
// Global Configuration and Variables
//=============================================//
const port = process.env.SERVER_PORT;
const peerRecord = {}; // Tracks { IP: { geo: {lat, long}, firstSeen, lastSeen } }
const clientRecord = {}; // Tracks { IP: [timestamps...] }
const banList = {}; // Tracks { IP: banExpiration }

//=============================================//
// Rate Limiting and Anti-DoS Settings
//=============================================//
const LOG_THRESHOLD = 10 * 1024 * 1024; // 10 MB log rotation size
const RATE_LIMIT = 5; // Max 5 requests per minute per IP
const WINDOW_MS = 60 * 1000; // Rate limiting window size (1 minute)
const MAX_CONN_PER_SECOND = 100; // Global DoS detection limit (requests per second)
const FLOOD_DELAY = 2000; // 2 second artificial delay for flooders
const RESPONSE_PEER_LIMIT = 20; // Max peers to send per client response
const PEER_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes inactivity removal
const LOG_ROTATION_DIR = path.join(process.cwd(), "logs");

//=============================================//
// Log Files
//=============================================//
const ERROR_LOG = path.join(LOG_ROTATION_DIR, "errors.log");
const REQUEST_LOG = path.join(LOG_ROTATION_DIR, "requests.log");
const SLOW_IP_LOG = path.join(LOG_ROTATION_DIR, "slow_ips.log");
const ABUSIVE_IP_LOG = path.join(LOG_ROTATION_DIR, "abusive_ips.log");
const BANNED_IP_LOG = path.join(LOG_ROTATION_DIR, "banned_ips.log");

//=============================================//
// Ensure Log Directory Exists
//=============================================//
function makeSureLogDir() {
  if (!fs.existsSync(LOG_ROTATION_DIR)) {
    fs.mkdirSync(LOG_ROTATION_DIR);
  }
}
makeSureLogDir();

//=============================================//
// Logging with Rotation
//=============================================//
function appendLog(file, msg) {
  fs.appendFileSync(file, msg);
  if (fs.statSync(file).size > LOG_THRESHOLD) {
    saveLogsToDB(file); // Offload logs to database
    fs.writeFileSync(file, ""); // Clear file after offloading
  }
}

//=============================================//
// Response Builder with Headers
//=============================================//
function buildResponse(statusObj, extraBody = {}) {
  return JSON.stringify({
    info: {
      timestamp: new Date().toISOString(),
      serverVersion: "v1.0",
    },
    statusCode: statusObj.code,
    message: statusObj.message,
    ...extraBody,
  });
}

//=============================================//
// Global DoS Request Counter
//=============================================//
let globalRequestCount = 0;
setInterval(() => {
  globalRequestCount = 0;
}, 1000); // Reset every second

//===================================================================================//
// Skip geo location lookup for private IPs since this API only works for public IPs (This is used for localhost testing)
//===================================================================================//
function isPrivateIP(ip) {
  return (
    ip.startsWith("127.") || // Loopback
    ip.startsWith("192.168.") || // Private range
    ip.startsWith("10.") || // Private range
    ip.startsWith("172.") || // Private range (some blocks)
    ip === "::1" // IPv6 localhost
  );
}

//=============================================//
// IP Geolocation Lookup (Using ipapi.co)
//=============================================//
async function getGeo(ip) {
  if (isPrivateIP(ip)) {
    return { latitude: 0, longitude: 0 }; // Dummy coords for local test
  }

  try {
    const res = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 3000, // Timeout after 3 seconds
    });
    const { latitude, longitude } = res.data;
    if (latitude && longitude) return { latitude, longitude };
  } catch (err) {
    appendLog(
      ERROR_LOG,
      `[${new Date().toISOString()}] Geo lookup failed for ${ip}: ${
        err.message
      }\n`
    );
  }
  return null;
}

//=============================================//
// Haversine Formula for Distance (km)
//=============================================//
function distance(a, b) {
  const R = 6371;
  const toRad = (x) => (x * Math.PI) / 180;
  const dLat = toRad(b.latitude - a.latitude);
  const dLon = toRad(b.longitude - a.longitude);
  const aa =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.latitude)) *
      Math.cos(toRad(b.latitude)) *
      Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(aa), Math.sqrt(1 - aa));
  return R * c;
}

//=============================================//
// Periodic Cleanup of Stale Peers
//=============================================//
setInterval(() => {
  const now = Date.now();
  for (const [ip, info] of Object.entries(peerRecord)) {
    if (now - info.lastSeen > PEER_TIMEOUT_MS) {
      appendLog(
        REQUEST_LOG,
        `[${new Date().toISOString()}] Removing stale peer: ${ip}\n`
      );
      delete peerRecord[ip];
    }
  }
}, 60000); // Run every 1 minute

//=============================================//
// TCP Server
//=============================================//
const server = net.createServer((sock) => {
  const ip = sock.remoteAddress;
  const now = Date.now();

  // Guard: Invalid or Banned IPs
  if (!ip || banList[ip] > now) {
    sock.end();
    return;
  }

  // Global DoS Protection (Requests Per Second)
  globalRequestCount++;
  if (globalRequestCount > MAX_CONN_PER_SECOND) {
    appendLog(
      ABUSIVE_IP_LOG,
      `[${new Date().toISOString()}] Global rate limit reached\n`
    );
    sock.write(buildResponse(STATUS_CODES.ERROR_GLOBAL_DOS));
    sock.end();
    return;
  }

  // Per-IP Rate Limiting
  if (!clientRecord[ip]) clientRecord[ip] = [];
  clientRecord[ip] = clientRecord[ip].filter((ts) => now - ts < WINDOW_MS);
  if (clientRecord[ip].length >= RATE_LIMIT) {
    appendLog(
      ABUSIVE_IP_LOG,
      `[${new Date().toISOString()}] IP rate limit exceeded: ${ip}\n`
    );
    sock.write(buildResponse(STATUS_CODES.ERROR_RATE_LIMIT));
    sock.end();
    clientRecord[ip].push(now);
    return;
  }
  clientRecord[ip].push(now);

  // Auto-Ban Abusive IPs
  if (clientRecord[ip].length > RATE_LIMIT * 3) {
    banList[ip] = now + WINDOW_MS * 10; // 10 minute ban
    appendLog(
      BANNED_IP_LOG,
      `[${new Date().toISOString()}] Auto-banned IP: ${ip}\n`
    );
  }

  // Slowloris Protection: 5 second timeout for clients sending nothing
  sock.setTimeout(5000);

  sock.on("timeout", () => {
    appendLog(
      SLOW_IP_LOG,
      `[${new Date().toISOString()}] Idle timeout from ${ip}\n`
    );
    sock.write(buildResponse(STATUS_CODES.ERROR_IDLE_TIMEOUT));
    sock.end();
  });

  sock.setEncoding("utf8");
  let dataBuffer = "";

  sock.on("data", async (data) => {
    dataBuffer += data;

    // Payload Size Guard
    if (dataBuffer.length > 2048) {
      appendLog(
        ABUSIVE_IP_LOG,
        `[${new Date().toISOString()}] Oversized payload from ${ip}\n`
      );
      sock.write(buildResponse(STATUS_CODES.ERROR_PAYLOAD_TOO_LARGE));
      sock.end();
      return;
    }

    // Apply Artificial Delay to Slow Down Flooders
    await new Promise((r) => setTimeout(r, FLOOD_DELAY));

    try {
      const msg = JSON.parse(dataBuffer.trim());

      //=================================//
      // Handle Client Actions
      //=================================//
      if (msg.action === "register") {
        let geo = (peerRecord[ip] && peerRecord[ip].geo) || (await getGeo(ip));

        if (geo) {
          peerRecord[ip] = {
            geo,
            firstSeen: now,
            lastSeen: now,
          };
          appendLog(
            REQUEST_LOG,
            `[${new Date().toISOString()}] Registered peer: ${ip}\n`
          );
        } else {
          sock.write(buildResponse(STATUS_CODES.ERROR_GEO_LOOKUP_FAILED));
          sock.end();
          return;
        }

        // Build List of Nearby Peers
        const peers = Object.entries(peerRecord)
          // Just return all IPs including the connectin guser IPS (It will be the fisrt index)
          //.filter(([k]) => k !== ip)
          .map(([k, v]) => ({ ip: k, ...v.geo }))
          .filter((v) => v.latitude && v.longitude);

        if (geo) {
          peers.sort((a, b) => distance(a, geo) - distance(b, geo));
        }

        const sendPeers = peers.slice(0, RESPONSE_PEER_LIMIT);
        sock.write(
          buildResponse(STATUS_CODES.SUCCESS_REGISTER, {
            yourIP: ip, // <-- Client's own IP
            peers: sendPeers,
          })
        );
      } else if (msg.action === "unregister") {
        if (peerRecord[ip]) {
          delete peerRecord[ip];
          appendLog(
            REQUEST_LOG,
            `[${new Date().toISOString()}] Unregistered peer: ${ip}\n`
          );
        }
        sock.write(buildResponse(STATUS_CODES.SUCCESS_UNREGISTER));
      } else if (msg.action === "heartbeat") {
        if (peerRecord[ip]) {
          peerRecord[ip].lastSeen = now;
          appendLog(
            REQUEST_LOG,
            `[${new Date().toISOString()}] Heartbeat from: ${ip}\n`
          );
        }
        sock.write(buildResponse(STATUS_CODES.SUCCESS_HEARTBEAT));
      } else {
        sock.write(buildResponse(STATUS_CODES.ERROR_UNKNOWN_ACTION));
      }
    } catch (err) {
      appendLog(
        ABUSIVE_IP_LOG,
        `[${new Date().toISOString()}] JSON parse error from ${ip}: ${
          err.message
        }\n`
      );
      sock.write(buildResponse(STATUS_CODES.ERROR_INVALID_JSON));
    } finally {
      sock.end();
    }
  });

  sock.on("error", (err) => {
    appendLog(
      ERROR_LOG,
      `[${new Date().toISOString()}] Socket error from ${ip}: ${err.message}\n`
    );
  });
});

//=============================================//
// Server Error Handling
//=============================================//
server.maxConnections = 1000;

server.on("error", (err) => {
  appendLog(
    ERROR_LOG,
    `[${new Date().toISOString()}] ServerErr: ${err.message}\n`
  );
});

//=============================================//
// Start Listening
//=============================================//
server.listen(port, "0.0.0.0", () =>
  console.log("Bootstrap server listening on ", server.address())
);

//=============================================//
// Global Exception and Rejection Catchers
//=============================================//
process.on("uncaughtException", (err) =>
  appendLog(ERROR_LOG, `UE: ${err.stack}\n`)
);

process.on("unhandledRejection", (reason) =>
  appendLog(ERROR_LOG, `UR: ${reason}\n`)
);
