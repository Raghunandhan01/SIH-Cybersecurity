import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import { initialTrafficData, rulesData, alertsData, metricsData, settingsData } from './data.js';

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' }
});

// REST Endpoints
app.get('/api/metrics', (req, res) => {
    res.json(metricsData);
});

app.get('/api/rules', (req, res) => {
    res.json(rulesData);
});

app.post('/api/rules', (req, res) => {
    // Generate a new ID and assign proper icon based on action
    const action = req.body.action || 'Block';
    let icon = 'ph-lock-key';
    let colorClass = 'text-red';
    
    if (action === 'Challenge (Captcha)') {
        icon = 'ph-robot';
        colorClass = 'text-warning';
    } else if (action === 'Log Only') {
        icon = 'ph-eye';
        colorClass = 'text-blue';
    }

    const newRule = { 
        id: `rule-${Date.now()}`, 
        name: req.body.name, 
        description: `Targeting: ${req.body.targetApp}. Conditions: Context aware policies applied.`, 
        icon,
        colorClass,
        status: 'Active', 
        updated: 'Just now',
        disabled: false
    };
    rulesData.unshift(newRule);
    res.status(201).json(newRule);
});

app.delete('/api/rules/:id', (req, res) => {
    const { id } = req.params;
    const index = rulesData.findIndex(r => r.id === id);
    if (index !== -1) {
        rulesData.splice(index, 1);
        res.status(200).json({ success: true });
    } else {
        res.status(404).json({ error: 'Rule not found' });
    }
});

app.get('/api/alerts', (req, res) => {
    res.json(alertsData);
});

app.get('/api/traffic/history', (req, res) => {
    res.json(initialTrafficData);
});

// Settings Endpoints
app.get('/api/settings', (req, res) => {
    res.json(settingsData);
});

app.post('/api/settings', (req, res) => {
    if (typeof req.body.autoBlock !== 'undefined') settingsData.autoBlock = req.body.autoBlock;
    if (typeof req.body.verboseLogging !== 'undefined') settingsData.verboseLogging = req.body.verboseLogging;
    if (typeof req.body.threatFeed !== 'undefined') settingsData.threatFeed = req.body.threatFeed;
    
    // Broadcast setting changes (optional feature)
    io.emit('settings-updated', settingsData);
    
    res.status(200).json({ success: true, settings: settingsData });
});

// Real-Time Event Ingestion Webhook
app.post('/api/traffic/ingest', (req, res) => {
    /* 
      Expected Payload:
      {
         "status": "allowed" | "blocked" | "flagged",
         "user": "string",
         "role": "string",
         "targetApp": "string",
         "route": "string",
         "clientIP": "string",
         "device": "string",
         "risk": "string",
         "serviceIcon": "ph-user"
      }
    */
    const eventParams = req.body;
    
    const newTraffic = {
        id: Date.now(),
        status: eventParams.status || 'flagged',
        user: eventParams.user || 'Unknown Source',
        role: eventParams.role || 'Unauthenticated',
        serviceIcon: eventParams.serviceIcon || 'ph-warning-circle',
        targetApp: eventParams.targetApp || 'Unknown App',
        route: eventParams.route || 'Unknown Route',
        clientIP: eventParams.clientIP || '0.0.0.0',
        device: eventParams.device || 'Unknown Device',
        risk: eventParams.risk || '-',
        time: 'Just now'
    };

    // Store it and push to socket
    initialTrafficData.unshift(newTraffic);
    if (initialTrafficData.length > 50) initialTrafficData.pop();
    io.emit('new-traffic', newTraffic);

    res.status(201).json({ success: true, message: "Traffic event ingested and broadcasted successfully.", event: newTraffic });
});

// WebSocket for live traffic
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);
    // Send initial history upon connection
    socket.emit('initial-traffic', initialTrafficData);
    
    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Simulate Live Traffic Every 5 Seconds
setInterval(() => {
    const statuses = ['allowed', 'blocked', 'flagged'];
    const users = ['system_agent', 'developer_mac', 'anonymous', 'service_api'];
    const risks = ['-', 'SQL Injection Attempt', 'Geo-blocked Region', 'Anomalous Volume', 'Missing Auth Header'];
    const routes = ['GET /api/users', 'POST /auth/login', 'PUT /data/sync', 'DELETE /records/old'];
    const apps = ['Internal Portal', 'Payment Gateway', 'HR System', 'Public API'];
    const icons = ['ph-user', 'ph-robot', 'ph-cpu', 'ph-desktop'];

    const statusObj = statuses[Math.floor(Math.random() * statuses.length)];
    const userRole = Math.random() > 0.5 ? 'System' : 'External';
    
    const newTraffic = {
        id: Date.now(),
        status: statusObj,
        user: users[Math.floor(Math.random() * users.length)],
        role: userRole,
        serviceIcon: icons[Math.floor(Math.random() * icons.length)],
        targetApp: apps[Math.floor(Math.random() * apps.length)],
        route: routes[Math.floor(Math.random() * routes.length)],
        clientIP: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        device: 'Auto-detected',
        risk: statusObj === 'allowed' ? '-' : risks[Math.floor(Math.random() * risks.length)],
        time: 'Just now'
    };
    
    // Add to history (keep history small for demo)
    initialTrafficData.unshift(newTraffic);
    if (initialTrafficData.length > 50) initialTrafficData.pop();

    // Broadcast to all connected clients
    io.emit('new-traffic', newTraffic);
}, 5000);

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Application-Context Aware Firewall backend running on port ${PORT}`);
});
