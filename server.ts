import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";

import { GoogleGenerativeAI } from "@google/generative-ai";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "");
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// Initialize Database
const db = new Database("firewall.db");

// Create Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );

  CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT, -- ALLOW, BLOCK, LIMIT
    target TEXT,
    reason TEXT,
    start_time TEXT DEFAULT '00:00',
    end_time TEXT DEFAULT '23:59',
    limit_kbps INTEGER DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    destination TEXT,
    protocol TEXT,
    application TEXT,
    size TEXT,
    status TEXT,
    country TEXT DEFAULT 'Unknown',
    country_code TEXT DEFAULT 'UN',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_data TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS ids_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT, -- SQLI, XSS, BRUTEFORCE, SCAN
    source TEXT,
    payload TEXT,
    severity TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Seed default settings
const autoProtect = db.prepare("SELECT * FROM settings WHERE key = ?").get("auto_protect");
if (!autoProtect) {
  db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run("auto_protect", "false");
}

// Migration: Ensure rules table has start_time and end_time
const tableInfo = db.prepare("PRAGMA table_info(rules)").all() as any[];
const hasStartTime = tableInfo.some(col => col.name === 'start_time');
if (!hasStartTime) {
  db.exec("ALTER TABLE rules ADD COLUMN start_time TEXT DEFAULT '00:00'");
  db.exec("ALTER TABLE rules ADD COLUMN end_time TEXT DEFAULT '23:59'");
}

const trafficInfo = db.prepare("PRAGMA table_info(traffic_logs)").all() as any[];
if (!trafficInfo.some(col => col.name === 'country')) {
  db.exec("ALTER TABLE traffic_logs ADD COLUMN country TEXT DEFAULT 'Unknown'");
  db.exec("ALTER TABLE traffic_logs ADD COLUMN country_code TEXT DEFAULT 'UN'");
}

const rulesInfo = db.prepare("PRAGMA table_info(rules)").all() as any[];
if (!rulesInfo.some(col => col.name === 'limit_kbps')) {
  db.exec("ALTER TABLE rules ADD COLUMN limit_kbps INTEGER DEFAULT 0");
}

// Seed default user if not exists
const userExists = db.prepare("SELECT * FROM users WHERE username = ?").get("Raghu");
if (!userExists) {
  db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run("Raghu", "password");
}

// Seed default rules if empty
const rulesCount = db.prepare("SELECT COUNT(*) as count FROM rules").get() as { count: number };
if (rulesCount.count === 0) {
  db.prepare("INSERT INTO rules (type, target, reason) VALUES (?, ?, ?)").run("BLOCK", "YouTube", "Policy: No Streaming");
  db.prepare("INSERT INTO rules (type, target, reason) VALUES (?, ?, ?)").run("ALLOW", "Gmail", "Business Essential");
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  let processingLogs: string[] = [];
  let featureLogs: Record<string, string[]> = {
    "app-id": [],
    "auth": [],
    "monitor": [],
    "policy": [],
    "threat": [],
    "context": []
  };

  const logFeature = (feature: string, msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    const fullMsg = `[${timestamp}] ${msg}`;
    featureLogs[feature] = [fullMsg, ...featureLogs[feature].slice(0, 9)];
    processingLogs = [fullMsg, ...processingLogs.slice(0, 19)];
  };

  // Processing Engine Simulation
  const processPacket = (packet: any) => {
    logFeature("monitor", `Packet from ${packet.source} intercepted.`);
    
    // Identification
    logFeature("app-id", `Analyzing traffic patterns for ${packet.source}...`);
    const identifiedApp = packet.application;
    logFeature("app-id", `Application detected: ${identifiedApp}`);

    // Contextual Analysis
    logFeature("context", `Analyzing user context for ${identifiedApp}...`);
    logFeature("context", `User 'Raghu' context verified.`);

    // Rule Engine
    logFeature("policy", `Checking policies for ${identifiedApp}...`);
    
    const currentTime = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    
    const rule = db.prepare(`
      SELECT * FROM rules 
      WHERE (target = ? OR target = ?) 
      AND (
        (start_time <= end_time AND ? BETWEEN start_time AND end_time) OR
        (start_time > end_time AND (? >= start_time OR ? <= end_time))
      )
    `).get(identifiedApp, packet.source, currentTime, currentTime, currentTime) as any;
    
    if (rule && rule.type === "BLOCK") {
      logFeature("policy", `BLOCK policy found. Dropping packet.`);
      packet.status = "BLOCKED";
    } else if (rule && rule.type === "LIMIT") {
      logFeature("policy", `LIMIT policy found (${rule.limit_kbps} KBps). Throttling traffic.`);
      packet.status = "THROTTLED";
    } else {
      logFeature("policy", `No block policy. Traffic ALLOWED.`);
      packet.status = "ALLOWED";
    }

    // Threat Detection
    if (packet.status === "BLOCKED" && Math.random() > 0.7) {
      const msg = `Alert! Repeated blocked attempts from ${packet.source}.`;
      logFeature("threat", msg);
      db.prepare("INSERT INTO alerts (level, message) VALUES (?, ?)").run("CRITICAL", msg);
    }

    // IDS Simulation (Signature Matching)
    const maliciousSignatures = [
      { pattern: "OR 1=1", type: "SQL Injection", severity: "CRITICAL" },
      { pattern: "<script>", type: "XSS Attack", severity: "HIGH" },
      { pattern: "../", type: "Path Traversal", severity: "HIGH" },
      { pattern: "admin/login", type: "Brute Force Attempt", severity: "MEDIUM" }
    ];

    const payload = packet.payload || "";
    const detected = maliciousSignatures.find(sig => payload.includes(sig.pattern));
    
    if (detected) {
      db.prepare("INSERT INTO ids_logs (type, source, payload, severity) VALUES (?, ?, ?, ?)").run(
        detected.type,
        packet.source,
        payload,
        detected.severity
      );
      db.prepare("INSERT INTO alerts (level, message) VALUES (?, ?)").run(
        detected.severity,
        `IDS Alert: ${detected.type} detected from ${packet.source}`
      );
      logFeature("threat", `IDS: ${detected.type} detected!`);
      packet.status = "BLOCKED"; // Force block if IDS catches it
    }

    // Store in DB
    db.prepare(`
      INSERT INTO traffic_logs (source, destination, protocol, application, size, status, country, country_code)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      packet.source, 
      packet.destination, 
      packet.protocol, 
      packet.application, 
      packet.size, 
      packet.status,
      packet.country || 'Unknown',
      packet.country_code || 'UN'
    );

    logFeature("monitor", `Event stored in SQLite database.`);
    return packet;
  };

  // API Routes
  app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ? AND password = ?").get(username, password);
    if (user) {
      res.json({ success: true, user: { username: (user as any).username } });
    } else {
      res.status(401).json({ success: false, message: "Invalid credentials" });
    }
  });

  app.get("/api/traffic", (req, res) => {
    const apps = ["Gmail", "YouTube", "Browser", "File Transfer", "Slack", "Zoom", "Netflix"];
    const countries = [
      { name: "United States", code: "US" },
      { name: "India", code: "IN" },
      { name: "Germany", code: "DE" },
      { name: "United Kingdom", code: "GB" },
      { name: "Japan", code: "JP" },
      { name: "Brazil", code: "BR" },
      { name: "Russia", code: "RU" }
    ];
    const country = countries[Math.floor(Math.random() * countries.length)];
    
    // Occasionally generate malicious payloads
    let payload = "";
    if (Math.random() > 0.85) {
      const payloads = ["' OR 1=1 --", "<script>alert(1)</script>", "../../../etc/passwd", "POST /admin/login HTTP/1.1"];
      payload = payloads[Math.floor(Math.random() * payloads.length)];
    }

    const rawPacket = {
      source: `192.168.1.${Math.floor(Math.random() * 255)}`,
      destination: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.10.23`,
      protocol: ["HTTPS", "HTTP", "SSH", "FTP", "DNS"][Math.floor(Math.random() * 5)],
      application: apps[Math.floor(Math.random() * apps.length)],
      size: `${(Math.random() * 10).toFixed(1)} KB`,
      status: "PENDING",
      country: country.name,
      country_code: country.code,
      payload: payload
    };
    
    processPacket(rawPacket);
    const traffic = db.prepare("SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT 50").all();
    res.json(traffic);
  });

  app.get("/api/feature-logs", (req, res) => res.json(featureLogs));
  app.get("/api/processing-logs", (req, res) => res.json(processingLogs));

  app.get("/api/modules", (req, res) => {
    res.json([
      { id: "auth", name: "User Authentication", status: "ACTIVE", load: "2%" },
      { id: "capture", name: "Traffic Capture (Scapy)", status: "ACTIVE", load: "14%" },
      { id: "detect", name: "Application Detection", status: "ACTIVE", load: "28%" },
      { id: "engine", name: "Rule Engine", status: "ACTIVE", load: "5%" },
      { id: "threat", name: "Threat Detection", status: "ACTIVE", load: "12%" },
      { id: "log", name: "Logging System (SQLite)", status: "ACTIVE", load: "1%" },
    ]);
  });

  app.get("/api/rules", (req, res) => {
    const rules = db.prepare("SELECT * FROM rules ORDER BY timestamp DESC").all();
    res.json(rules);
  });
  
  app.post("/api/rules", (req, res) => {
    const { type, target, reason, start_time, end_time, limit_kbps } = req.body;
    const info = db.prepare("INSERT INTO rules (type, target, reason, start_time, end_time, limit_kbps) VALUES (?, ?, ?, ?, ?, ?)").run(
      type, 
      target, 
      reason, 
      start_time || '00:00', 
      end_time || '23:59',
      limit_kbps || 0
    );
    
    db.prepare("INSERT INTO audit_logs (action, details) VALUES (?, ?)").run(
      "RULE_CREATED", 
      `Type: ${type}, Target: ${target}, Reason: ${reason}`
    );

    const newRule = db.prepare("SELECT * FROM rules WHERE id = ?").get(info.lastInsertRowid);
    res.status(201).json(newRule);
  });

  app.delete("/api/rules/:id", (req, res) => {
    const rule = db.prepare("SELECT * FROM rules WHERE id = ?").get(req.params.id) as any;
    if (rule) {
      db.prepare("INSERT INTO audit_logs (action, details) VALUES (?, ?)").run(
        "RULE_DELETED", 
        `Target: ${rule.target}, Type: ${rule.type}`
      );
    }
    db.prepare("DELETE FROM rules WHERE id = ?").run(req.params.id);
    res.status(204).send();
  });

  app.get("/api/alerts", (req, res) => {
    const alerts = db.prepare("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20").all();
    res.json(alerts);
  });

  app.delete("/api/alerts/:id", (req, res) => {
    db.prepare("DELETE FROM alerts WHERE id = ?").run(req.params.id);
    res.status(204).send();
  });

  app.get("/api/stats", (req, res) => {
    const totalTraffic = (db.prepare("SELECT COUNT(*) as count FROM traffic_logs").get() as any).count + 15420;
    const blockedRequests = (db.prepare("SELECT COUNT(*) as count FROM traffic_logs WHERE status = 'BLOCKED'").get() as any).count + 124;
    const threatAlerts = (db.prepare("SELECT COUNT(*) as count FROM alerts").get() as any).count;
    
    const geoStats = db.prepare(`
      SELECT country as name, COUNT(*) as value 
      FROM traffic_logs 
      GROUP BY country 
      ORDER BY value DESC 
      LIMIT 5
    `).all();

    // Bandwidth Stats
    const totalSize = db.prepare("SELECT SUM(CAST(REPLACE(size, ' KB', '') AS FLOAT)) as total FROM traffic_logs").get() as any;
    const throttledSize = db.prepare("SELECT SUM(CAST(REPLACE(size, ' KB', '') AS FLOAT)) as total FROM traffic_logs WHERE status = 'THROTTLED'").get() as any;

    res.json({
      totalTraffic,
      blockedRequests,
      activeUsers: 12,
      threatAlerts,
      uptime: "14d 6h 22m",
      bandwidth: {
        total: (totalSize.total || 0).toFixed(2),
        throttled: (throttledSize.total || 0).toFixed(2)
      },
      trafficHistory: Array.from({ length: 7 }, (_, i) => ({
        name: `Day ${i + 1}`,
        allowed: Math.floor(Math.random() * 1000) + 500,
        blocked: Math.floor(Math.random() * 200) + 50,
        throttled: Math.floor(Math.random() * 100) + 20,
      })),
      appUsage: [
        { name: "Browser", value: 45 },
        { name: "Gmail", value: 25 },
        { name: "YouTube", value: 15 },
        { name: "Others", value: 15 },
      ],
      geoStats
    });
  });

  app.post("/api/ai-analyze", async (req, res) => {
    try {
      // Optimize: Only send last 15 logs and essential rule info to speed up processing
      const traffic = db.prepare("SELECT source, application, protocol, status FROM traffic_logs ORDER BY timestamp DESC LIMIT 15").all();
      const rules = db.prepare("SELECT type, target FROM rules").all();
      
      const prompt = `
        Analyze these firewall logs/rules and return JSON.
        LOGS: ${JSON.stringify(traffic)}
        RULES: ${JSON.stringify(rules)}
        JSON format: {"summary": "brief text", "threats": ["short text"], "suggestions": [{"type": "BLOCK", "target": "IP/App", "reason": "short text"}]}
      `;

      const result = await model.generateContent(prompt);
      const response = result.response;
      const text = response.text();
      
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const aiData = JSON.parse(jsonMatch[0]);
        
        // Auto-Protect Logic
        const autoProtect = db.prepare("SELECT value FROM settings WHERE key = ?").get("auto_protect") as any;
        if (autoProtect && autoProtect.value === "true") {
          aiData.suggestions.forEach((s: any) => {
            if (s.type === "BLOCK") {
              const exists = db.prepare("SELECT * FROM rules WHERE target = ?").get(s.target);
              if (!exists) {
                db.prepare("INSERT INTO rules (type, target, reason) VALUES (?, ?, ?)").run("BLOCK", s.target, `AI Auto-Protect: ${s.reason}`);
                db.prepare("INSERT INTO audit_logs (action, details) VALUES (?, ?)").run("AUTO_PROTECT", `AI automatically blocked ${s.target}`);
              }
            }
          });
        }

        res.json(aiData);
      } else {
        res.status(500).json({ error: "Failed to parse AI response" });
      }
    } catch (error) {
      console.error("AI Analysis failed:", error);
      res.status(500).json({ error: "AI Analysis failed" });
    }
  });

  app.post("/api/vulnerability-scan", async (req, res) => {
    try {
      const prompt = `
        Simulate a network vuln scan. Return JSON array of 4 findings.
        JSON format: [{"name": "str", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "device": "IP", "description": "short", "remediation": "short"}]
      `;

      const result = await model.generateContent(prompt);
      const text = result.response.text();
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      
      if (jsonMatch) {
        const scanData = JSON.parse(jsonMatch[0]);
        db.prepare("INSERT INTO scan_history (scan_data) VALUES (?)").run(JSON.stringify(scanData));
        db.prepare("INSERT INTO audit_logs (action, details) VALUES (?, ?)").run("VULN_SCAN", `Completed scan with ${scanData.length} findings`);
        res.json(scanData);
      } else {
        res.status(500).json({ error: "Failed to parse scan results" });
      }
    } catch (error) {
      console.error("Vulnerability scan failed:", error);
      res.status(500).json({ error: "Vulnerability scan failed" });
    }
  });

  app.get("/api/scan-history", (req, res) => {
    const history = db.prepare("SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT 10").all();
    res.json(history.map((h: any) => ({ ...h, scan_data: JSON.parse(h.scan_data) })));
  });

  app.get("/api/audit-logs", (req, res) => {
    const logs = db.prepare("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50").all();
    res.json(logs);
  });

  app.get("/api/settings", (req, res) => {
    const settings = db.prepare("SELECT * FROM settings").all();
    const settingsObj = settings.reduce((acc: any, s: any) => {
      acc[s.key] = s.value;
      return acc;
    }, {});
    res.json(settingsObj);
  });

  app.post("/api/settings", (req, res) => {
    const { key, value } = req.body;
    db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").run(key, String(value));
    db.prepare("INSERT INTO audit_logs (action, details) VALUES (?, ?)").run("SETTING_CHANGED", `${key} set to ${value}`);
    res.json({ success: true });
  });

  app.get("/api/ids-logs", (req, res) => {
    const logs = db.prepare("SELECT * FROM ids_logs ORDER BY timestamp DESC LIMIT 50").all();
    res.json(logs);
  });

  app.get("/api/report", (req, res) => {
    const logs = db.prepare("SELECT * FROM traffic_logs ORDER BY timestamp DESC").all() as any[];
    const headers = "ID,Source,Destination,Protocol,Application,Size,Status,Timestamp\n";
    const csv = logs.map(l => 
      `${l.id},${l.source},${l.destination},${l.protocol},${l.application},${l.size},${l.status},${l.timestamp}`
    ).join("\n");
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=firewall-report.csv');
    res.send(headers + csv);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
