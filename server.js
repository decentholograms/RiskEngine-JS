import express from 'express';
import { 
    RiskEngine, 
    BehaviorAnalyzer, 
    PatternDetector, 
    RateLimiter, 
    Fingerprinter,
    MathUtils 
} from './src/index.js';
import createAntiAbuseMiddleware from './src/middleware/antiAbuse.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const riskEngine = new RiskEngine({
    thresholds: {
        low: 0.25,
        medium: 0.5,
        high: 0.7,
        critical: 0.9
    },
    weights: {
        behavior: 0.25,
        patterns: 0.25,
        rateLimit: 0.2,
        fingerprint: 0.15,
        reputation: 0.15
    },
    rateLimit: {
        defaultLimit: 100,
        windowSize: 60000,
        burstMultiplier: 2
    },
    onHighRisk: (decision) => {
        console.log(`[ALERT] High risk detected for user ${decision.userId}: ${decision.riskScore.toFixed(3)}`);
    },
    onBlock: (decision) => {
        console.log(`[BLOCKED] User ${decision.userId} - Reason: ${decision.action.reason}`);
    }
});

const antiAbuse = createAntiAbuseMiddleware({
    engine: riskEngine,
    trustProxy: true,
    skipPaths: ['/health', '/metrics'],
    onDecision: (decision, req, res) => {
        if (decision.riskScore > 0.5) {
            console.log(`[RISK] ${req.method} ${req.path} - Score: ${decision.riskScore.toFixed(3)} - Level: ${decision.riskLevel}`);
        }
    }
});

app.use(antiAbuse);

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

app.get('/metrics', (req, res) => {
    const stats = riskEngine.getStats();
    res.json({
        engine: stats,
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

app.get('/api/users', (req, res) => {
    res.json({
        users: [
            { id: 1, name: 'User 1' },
            { id: 2, name: 'User 2' }
        ],
        riskDecision: req.riskDecision ? {
            score: req.riskDecision.riskScore,
            level: req.riskDecision.riskLevel
        } : null
    });
});

app.get('/api/users/:id', (req, res) => {
    res.json({
        id: req.params.id,
        name: `User ${req.params.id}`,
        riskDecision: req.riskDecision ? {
            score: req.riskDecision.riskScore,
            level: req.riskDecision.riskLevel
        } : null
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Missing credentials' });
    }

    res.json({
        success: true,
        token: 'fake-jwt-token',
        riskDecision: req.riskDecision ? {
            score: req.riskDecision.riskScore,
            level: req.riskDecision.riskLevel,
            action: req.riskDecision.action.type
        } : null
    });
});

app.post('/api/payment', (req, res) => {
    const decision = req.riskDecision;
    
    if (decision && decision.riskScore > 0.6) {
        return res.status(403).json({
            error: 'Payment blocked due to security concerns',
            riskScore: decision.riskScore,
            requiresVerification: true
        });
    }

    res.json({
        success: true,
        transactionId: Math.random().toString(36).substring(7),
        riskAssessment: {
            score: decision?.riskScore || 0,
            level: decision?.riskLevel || 'unknown'
        }
    });
});

app.get('/api/search', (req, res) => {
    res.json({
        query: req.query.q,
        results: [],
        riskDecision: req.riskDecision ? {
            score: req.riskDecision.riskScore,
            level: req.riskDecision.riskLevel
        } : null
    });
});

app.get('/api/profile/:userId', async (req, res) => {
    const profile = await riskEngine.getUserProfile(req.params.userId);
    res.json(profile);
});

app.post('/api/admin/reset-user/:userId', async (req, res) => {
    riskEngine.resetUser(req.params.userId);
    res.json({ success: true, message: `User ${req.params.userId} reset` });
});

app.get('/api/admin/config', (req, res) => {
    res.json(riskEngine.exportConfig());
});

app.post('/api/admin/config', (req, res) => {
    riskEngine.importConfig(req.body);
    res.json({ success: true, config: riskEngine.exportConfig() });
});

app.get('/demo/simulate-attack', async (req, res) => {
    const attackType = req.query.type || 'bruteforce';
    const results = [];

    console.log(`[DEMO] Simulating ${attackType} attack...`);

    for (let i = 0; i < 50; i++) {
        const fakeRequest = {
            ip: '192.168.1.100',
            userId: 'attacker-demo',
            method: 'POST',
            path: attackType === 'bruteforce' ? '/api/login' : '/api/users/' + i,
            endpoint: attackType === 'bruteforce' ? 'POST:/api/login' : `GET:/api/users/${i}`,
            action: attackType === 'bruteforce' ? 'login' : 'users',
            headers: {
                'user-agent': 'Mozilla/5.0 (Attack Simulation)'
            },
            body: attackType === 'bruteforce' ? { username: 'admin', password: `pass${i}` } : null
        };

        const decision = await riskEngine.evaluate(fakeRequest);
        
        results.push({
            iteration: i + 1,
            riskScore: decision.riskScore,
            riskLevel: decision.riskLevel,
            action: decision.action.type,
            allowed: decision.allowed
        });

        if (!decision.allowed) {
            console.log(`[DEMO] Attack blocked at iteration ${i + 1}`);
            break;
        }
    }

    riskEngine.resetUser('attacker-demo');

    res.json({
        attackType,
        totalAttempts: results.length,
        blocked: !results[results.length - 1].allowed,
        results: results.slice(-10),
        finalStats: riskEngine.getStats()
    });
});

app.get('/demo/fingerprint', (req, res) => {
    const fingerprinter = new Fingerprinter();
    
    const fingerprint = fingerprinter.generate({
        ip: req.ip,
        headers: req.headers,
        client: {
            timezone: req.headers['x-timezone'],
            screenResolution: req.headers['x-screen-resolution']
        }
    });

    res.json({
        fingerprint: fingerprint.fingerprint,
        confidence: fingerprint.confidence,
        isBot: fingerprint.isBot,
        anomalyScore: fingerprint.anomalyScore,
        components: {
            userAgent: fingerprint.components.userAgent?.parsed,
            ipClass: fingerprint.components.ipClass,
            platform: fingerprint.components.platform
        }
    });
});

app.get('/demo/behavior-analysis', async (req, res) => {
    const analyzer = new BehaviorAnalyzer();
    
    const normalEvents = [];
    let timestamp = Date.now() - 3600000;
    
    for (let i = 0; i < 100; i++) {
        timestamp += Math.random() * 30000 + 5000;
        normalEvents.push({
            timestamp,
            action: ['view', 'click', 'scroll', 'navigate'][Math.floor(Math.random() * 4)],
            endpoint: ['/home', '/products', '/about', '/contact'][Math.floor(Math.random() * 4)],
            responseTime: Math.random() * 500 + 100
        });
    }

    const normalResult = analyzer.analyze('normal-user', normalEvents);

    const botEvents = [];
    timestamp = Date.now() - 3600000;
    
    for (let i = 0; i < 100; i++) {
        timestamp += 1000;
        botEvents.push({
            timestamp,
            action: 'scrape',
            endpoint: `/api/products/${i}`,
            responseTime: 50
        });
    }

    const botResult = analyzer.analyze('bot-user', botEvents);

    res.json({
        normalUser: {
            riskScore: normalResult.riskScore,
            reliable: normalResult.reliable,
            metrics: normalResult.metrics
        },
        botUser: {
            riskScore: botResult.riskScore,
            reliable: botResult.reliable,
            factors: botResult.factors,
            metrics: botResult.metrics
        }
    });
});

app.get('/demo/pattern-detection', (req, res) => {
    const detector = new PatternDetector();
    
    const bruteForceEvents = [];
    let timestamp = Date.now();
    
    for (let i = 0; i < 30; i++) {
        bruteForceEvents.push({
            timestamp: timestamp + i * 500,
            action: 'login',
            endpoint: '/api/login',
            payload: { username: 'admin', password: `password${i}` }
        });
    }

    const result = detector.detect(bruteForceEvents);

    res.json({
        patternsDetected: result.patterns.length,
        riskScore: result.riskScore,
        attackType: result.attackType,
        patterns: result.patterns.slice(0, 5),
        metrics: result.metrics
    });
});

app.get('/demo/rate-limiter', async (req, res) => {
    const limiter = new RateLimiter({
        defaultLimit: 10,
        windowSize: 10000
    });

    const results = [];
    const identifier = 'test-user-' + Date.now();

    for (let i = 0; i < 20; i++) {
        const result = limiter.check(identifier);
        results.push({
            attempt: i + 1,
            allowed: result.allowed,
            remaining: result.remaining,
            resetIn: result.resetIn
        });
    }

    const status = limiter.getStatus(identifier);
    limiter.destroy();

    res.json({
        results,
        finalStatus: status,
        blockedAt: results.findIndex(r => !r.allowed) + 1
    });
});

app.use((err, req, res, next) => {
    console.error('[ERROR]', err);
    res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║              Risk Engine Anti-Abuse System                ║
╠═══════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${PORT}                  ║
╠═══════════════════════════════════════════════════════════╣
║  Endpoints:                                               ║
║  • GET  /health              - Health check               ║
║  • GET  /metrics             - System metrics             ║
║  • GET  /api/users           - List users                 ║
║  • POST /api/login           - Login endpoint             ║
║  • POST /api/payment         - Payment (risk-protected)   ║
║  • GET  /api/profile/:id     - User risk profile          ║
╠═══════════════════════════════════════════════════════════╣
║  Demo Endpoints:                                          ║
║  • GET /demo/simulate-attack?type=bruteforce              ║
║  • GET /demo/fingerprint                                  ║
║  • GET /demo/behavior-analysis                            ║
║  • GET /demo/pattern-detection                            ║
║  • GET /demo/rate-limiter                                 ║
╚═══════════════════════════════════════════════════════════╝
    `);
});

export default app;
