import express from "express";
import { createServer as createViteServer } from "vite";
import { Server as SocketServer } from "socket.io";
import { createServer as createHttpServer } from "http";
import { GoogleGenAI, Type } from "@google/genai";
import dns from "dns";
import net from "net";
import { promisify } from "util";
import Database from "better-sqlite3";

const resolve4 = promisify(dns.resolve4);

const db = new Database("scans.db");

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    domain TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    analysis TEXT,
    attack_paths TEXT,
    raw_results TEXT,
    discovered_subdomains TEXT,
    discovered_services TEXT
  )
`);

const app = express();
app.use(express.json());
const httpServer = createHttpServer(app);
const io = new SocketServer(httpServer, {
  cors: {
    origin: "*",
  },
});

const PORT = 3000;

// API Routes for History
app.get("/api/scans", (req, res) => {
  try {
    const scans = db.prepare("SELECT id, domain, timestamp FROM scans ORDER BY timestamp DESC").all();
    res.json(scans);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch scans" });
  }
});

app.get("/api/scans/:id", (req, res) => {
  try {
    const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(req.params.id);
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    
    res.json({
      ...scan,
      analysis: JSON.parse(scan.analysis),
      raw_results: JSON.parse(scan.raw_results),
      discovered_subdomains: JSON.parse(scan.discovered_subdomains),
      discovered_services: JSON.parse(scan.discovered_services)
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch scan details" });
  }
});

// AI Initialization
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });

// Common subdomains for discovery
const COMMON_SUBDOMAINS = [
  "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
  "vpn", "m", "shop", "ftp", "dev", "staging", "api", "test", "portal", "admin",
  "support", "cloud", "app", "status", "docs", "beta", "git", "gitlab", "jenkins"
];

// Common ports to scan
const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 9000, 27017
];

async function scanPort(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(1000);
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

async function discoverSubdomains(domain: string, socket: any) {
  const discovered: string[] = [];
  socket.emit("scan:progress", { message: "Starting subdomain discovery...", progress: 10 });
  
  // Always add the main domain
  discovered.push(domain);

  for (let i = 0; i < COMMON_SUBDOMAINS.length; i++) {
    const sub = `${COMMON_SUBDOMAINS[i]}.${domain}`;
    try {
      await resolve4(sub);
      discovered.push(sub);
      socket.emit("scan:update", { type: "subdomain", value: sub });
    } catch (e) {
      // Ignore
    }
    const progress = 10 + Math.floor((i / COMMON_SUBDOMAINS.length) * 30);
    socket.emit("scan:progress", { message: `Checking ${sub}...`, progress });
  }
  return discovered;
}

async function scanHosts(hosts: string[], socket: any) {
  const results: any[] = [];
  socket.emit("scan:progress", { message: "Scanning discovered hosts for open services...", progress: 40 });

  for (let i = 0; i < hosts.length; i++) {
    const host = hosts[i];
    const openPorts: number[] = [];
    for (const port of COMMON_PORTS) {
      const isOpen = await scanPort(host, port);
      if (isOpen) {
        openPorts.push(port);
        socket.emit("scan:update", { type: "service", host, port });
      }
    }
    results.push({ host, openPorts });
    const progress = 40 + Math.floor((i / hosts.length) * 40);
    socket.emit("scan:progress", { message: `Scanned ${host}`, progress });
  }
  return results;
}

io.on("connection", (socket) => {
  console.log("Client connected");

  socket.on("scan:start", async ({ domain }) => {
    try {
      socket.emit("scan:progress", { message: "Initializing scan...", progress: 5 });

      // 1. Subdomain Discovery
      const subdomains = await discoverSubdomains(domain, socket);

      // 2. Service Discovery
      const scanResults = await scanHosts(subdomains, socket);

      // 3. AI Risk Analysis
      socket.emit("scan:progress", { message: "Analyzing risks with AI...", progress: 85 });
      
      const scanDataString = JSON.stringify(scanResults, null, 2);
      
      const analysisResponse = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `You are a senior cybersecurity penetration tester.
Analyze the following reconnaissance and vulnerability scan results.

Tasks:
1. Identify potential security risks
2. Prioritize vulnerabilities based on exploitation likelihood
3. Assign severity levels (Low / Medium / High / Critical)
4. Explain the impact of each issue
5. Provide remediation recommendations

Scan data:
${scanDataString}`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              risks: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    title: { type: Type.STRING },
                    severity: { type: Type.STRING },
                    impact: { type: Type.STRING },
                    remediation: { type: Type.STRING },
                    host: { type: Type.STRING },
                    cveId: { type: Type.STRING, description: "CVE ID if applicable (e.g., CVE-2023-1234)" },
                    nvdLink: { type: Type.STRING, description: "Link to NVD entry if CVE exists" },
                    cvssScore: { type: Type.NUMBER, description: "CVSS score if available" }
                  },
                  required: ["title", "severity", "impact", "remediation"]
                }
              },
              summary: { type: Type.STRING }
            },
            required: ["risks", "summary"]
          }
        }
      });

      const analysis = JSON.parse(analysisResponse.text);

      // 4. Attack Path Analysis
      socket.emit("scan:progress", { message: "Mapping attack paths...", progress: 95 });
      const attackPathResponse = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `You are a red team security expert.
Based on the following attack surface data, identify possible attack paths an attacker could use.

Explain:
1. possible entry points
2. privilege escalation opportunities
3. sensitive assets exposed
4. potential lateral movement paths

Attack surface data:
${scanDataString}`,
      });

      const scanId = `ASR-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
      
      // Save to database
      db.prepare(`
        INSERT INTO scans (id, domain, analysis, attack_paths, raw_results, discovered_subdomains, discovered_services)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        scanId,
        domain,
        JSON.stringify(analysis),
        attackPathResponse.text,
        JSON.stringify(scanResults),
        JSON.stringify(subdomains),
        JSON.stringify(scanResults.flatMap(r => r.openPorts.map(p => ({ host: r.host, port: p }))))
      );

      socket.emit("scan:complete", {
        id: scanId,
        analysis,
        attackPaths: attackPathResponse.text,
        rawResults: scanResults,
        subdomains,
        services: scanResults.flatMap(r => r.openPorts.map(p => ({ host: r.host, port: p })))
      });

    } catch (error: any) {
      console.error("Scan error:", error);
      socket.emit("scan:error", { message: error.message });
    }
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
  }

  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
