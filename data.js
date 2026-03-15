export const initialTrafficData = [
    {
        status: 'blocked',
        user: 'unknown_external',
        role: 'Unauthenticated',
        serviceIcon: 'ph-user-minus',
        targetApp: 'HR Finance Module',
        route: 'POST /api/v2/payroll/export',
        clientIP: '192.168.45.12 (GEO: RU)',
        device: 'Unknown Device',
        risk: 'Missing Auth Token + Geo Block',
        time: 'Just now'
    },
    {
        status: 'allowed',
        user: 'alice_smith (Sales)',
        role: 'Sales Rep',
        serviceIcon: 'ph-user',
        targetApp: 'CRM System',
        route: 'GET /api/v1/customers/list',
        clientIP: '10.0.4.15 (Corp VPN)',
        device: 'Managed Mac (Compliant)',
        risk: '-',
        time: '2 sec ago'
    },
    {
        status: 'flagged',
        user: 'service_billing_job',
        role: 'Machine Identity',
        serviceIcon: 'ph-cpu',
        targetApp: 'Payment Gateway',
        route: 'PUT /api/v1/ledger/update',
        clientIP: '10.0.8.22 (K8s Node-3)',
        device: 'Container App',
        risk: 'Anomalous Data Volume',
        time: '15 sec ago'
    },
    {
        status: 'blocked',
        user: 'bob_jones (Dev)',
        role: 'Developer Admin',
        serviceIcon: 'ph-user-gear',
        targetApp: 'Prod Database Proxy',
        route: 'SQL: DROP TABLE users',
        clientIP: '10.0.12.5 (Internal LAN)',
        device: 'Personal BYOD (Non-Compliant)',
        risk: 'SQL Injection pattern detected',
        time: '1 min ago'
    },
    {
        status: 'allowed',
        user: 'API Gateway (Edge)',
        role: 'Ingress Controller',
        serviceIcon: 'ph-arrows-left-right',
        targetApp: 'Frontend Microservice',
        route: 'GET /assets/style.css',
        clientIP: '10.20.1.1',
        device: 'Internal Gateway',
        risk: '-',
        time: '1 min ago'
    }
];

export const rulesData = [
    {
        id: "rule-1",
        name: "Block Legacy Auth",
        description: "Deny Basic Auth to all internal APIs except from Whitelisted IPs.",
        icon: "ph-lock-key",
        colorClass: "text-red",
        status: "Active",
        updated: "Updated 2 days ago",
        disabled: false
    },
    {
        id: "rule-2",
        name: "Geo-Fence HR System",
        description: "Restrict HR System access to US and EU regions only.",
        icon: "ph-globe-hemisphere-west",
        colorClass: "text-orange",
        status: "Active",
        updated: "Updated 1 week ago",
        disabled: false
    },
    {
        id: "rule-3",
        name: "Strict Bot Mitigation",
        description: "Enforce advanced JS challenges for anomalous headless browser traffic.",
        icon: "ph-robot",
        colorClass: "dark",
        status: "Disabled",
        updated: "Updated 1 month ago",
        disabled: true
    }
];

export const alertsData = [
    {
        id: "alert-1",
        severity: "critical",
        icon: "ph-warning-octagon",
        title: "Credential Stuffing Attack Detected",
        time: "2 mins ago",
        description: "High-volume login failures distributed across 50+ IPs targeting the Customer Portal. The system automatically engaged dynamic rate limiting.",
        tags: ["Identity", "BotNet"]
    },
    {
        id: "alert-2",
        severity: "high",
        icon: "ph-shield-warning",
        title: "Unusual Data Exfiltration Volume",
        time: "45 mins ago",
        description: "User 'bob_jones (Dev)' accessed 4,000+ sensitive records from the Billing App in under 5 minutes from an unmanaged device.",
        tags: ["DLP", "Insider Threat"]
    },
    {
        id: "alert-3",
        severity: "high",
        icon: "ph-shield-warning",
        title: "Cross-Site Scripting Payload",
        time: "2 hours ago",
        description: "Intercepted a request matching highly dangerous XSS signatures aiming at the Employee Directory search parameter.",
        tags: ["WAF", "OWASP Top 10"]
    }
];

export const metricsData = {
    totalRequests: "124.5K",
    requestsTrend: "+12.5%",
    blockedThreats: "3,142",
    blockedTrend: "+5.2%",
    anomalousUsers: "18",
    anomalousTrend: "-2",
    activePolicies: "42",
    policiesTrend: "Stable"
};

export const settingsData = {
    autoBlock: true,
    verboseLogging: false,
    threatFeed: "real-time"
};
