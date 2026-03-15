import express from 'express';
import fetch from 'node-fetch'; // We will use native fetch or dynamic import

const app = express();
app.use(express.json());

// --- Simulated Auth Middleware ---
// In a real environment, this decodes a JWT or reads session cookies.
const simulateAuth = (req, res, next) => {
    // We mock reading a token from headers
    const authHeader = req.headers['authorization'];
    
    // Default context
    req.userContext = {
        user: 'unknown_user',
        role: 'Unauthenticated',
        device: 'Unknown Device',
        clientIP: req.ip || '192.168.1.100'
    };

    if (authHeader && authHeader.includes('Bob-Sales-Token')) {
        req.userContext = {
            user: 'Bob (Sales Rep)',
            role: 'Sales',
            device: 'Managed Mac (Compliant)',
            clientIP: '10.0.4.15 (Corp VPN)'
        };
    } else if (authHeader && authHeader.includes('Alice-HR-Token')) {
        req.userContext = {
            user: 'Alice (HR Admin)',
            role: 'HR',
            device: 'Windows Laptop (Compliant)',
            clientIP: '10.0.5.22 (Office LAN)'
        };
    }

    next();
};

// --- Simulated WAF / Rule Evaluator ---
// In a real proxy, it might query a local cache synced from our Firewall Backend
const evaluateFirewallRules = async (req, res, next) => {
    let action = 'allowed';
    let riskReason = '-';
    
    // Simulate fetching rules from our Centralized Backend (or checking local cache)
    try {
        const rulesResponse = await fetch('http://localhost:3000/api/rules');
        const activeRules = await rulesResponse.json();
        
        // Very basic rule evaluation simulation against our context
        for (const rule of activeRules) {
            if (rule.disabled) continue;
            
            // Example: Block if targeting restricted app and lacking correct role
            if (rule.name.includes("Geo-Fence") && req.userContext.clientIP.includes("GEO: RU")) {
                action = 'blocked';
                riskReason = 'Geo-blocked Region';
                break;
            }
            if (rule.name.includes("Block Legacy") && req.userContext.role === 'Unauthenticated') {
                action = 'blocked';
                riskReason = 'Missing Auth Token';
                break;
            }
            // If the frontend user created a rule with 'Targeting: HR System'
            if (req.originalUrl.includes('/api/hr') && req.userContext.role !== 'HR' && rule.description.includes('HR System')) {
                action = rule.icon === 'ph-robot' ? 'flagged' : 'blocked';
                riskReason = 'Unauthorized Role Access Attempt';
                break;
            }
        }
    } catch (e) {
        console.warn("Could not reach Firewall Central Backend to sync rules.");
    }

    req.firewallAction = action;
    req.firewallRisk = riskReason;
    
    next();
};

// --- Simulated Filebeat / Log Forwarder ---
// In a real setup, Nginx writes to access.log and Filebeat sends it. 
// We will just do the POST directly here for the simulation.
const generateEnrichedLog = async (req) => {
    const logEntry = {
        status: req.firewallAction,
        user: req.userContext.user,
        role: req.userContext.role,
        targetApp: req.originalUrl.includes('/api/customers') ? 'CRM System' : 
                   req.originalUrl.includes('/api/hr') ? 'HR Platform' : 'Public API',
        route: `${req.method} ${req.originalUrl}`,
        clientIP: req.userContext.clientIP,
        device: req.userContext.device,
        risk: req.firewallRisk,
        serviceIcon: req.userContext.role !== 'Unauthenticated' ? 'ph-user' : 'ph-user-minus'
    };

    console.log(`[PROXY LOG ENRICHED]: ${JSON.stringify(logEntry)}`);

    try {
        await fetch('http://localhost:3000/api/traffic/ingest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(logEntry)
        });
    } catch (e) {
        console.error("Failed to forward log to Central Firewall:", e.message);
    }
};

// Apply middlewares
app.use(simulateAuth);
app.use(evaluateFirewallRules);

// --- Proxied Routes ---
app.get('/api/customers', async (req, res) => {
    await generateEnrichedLog(req);
    
    if (req.firewallAction === 'blocked') {
        return res.status(403).json({ error: "Access Denied by Centralized Firewall - " + req.firewallRisk });
    }
    
    res.json({ data: ["Customer A", "Customer B", "Customer C"] });
});

app.post('/api/hr/payroll', async (req, res) => {
    await generateEnrichedLog(req);
    
    if (req.firewallAction === 'blocked') {
        return res.status(403).json({ error: "Access Denied by Centralized Firewall - " + req.firewallRisk });
    }
    
    res.json({ success: true, message: "Payroll updated" });
});

const PORT = 4000;
app.listen(PORT, () => {
    console.log(`Mock Nginx Edge Proxy running on port ${PORT}`);
    console.log(`\nTo simulate Bob accessing customers:\n  curl -H "Authorization: Bearer Bob-Sales-Token" http://localhost:4000/api/customers`);
    console.log(`\nTo simulate a malicious payload:\n  curl -X POST http://localhost:4000/api/hr/payroll`);
});
