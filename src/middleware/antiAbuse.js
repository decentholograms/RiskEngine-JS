import RiskEngine from '../core/RiskEngine.js';

function createAntiAbuseMiddleware(options = {}) {
    const engine = options.engine || new RiskEngine(options);
    
    const config = {
        blockStatusCode: options.blockStatusCode || 403,
        challengeStatusCode: options.challengeStatusCode || 429,
        throttleDelay: options.throttleDelay || 1000,
        trustProxy: options.trustProxy || false,
        skipPaths: options.skipPaths || [],
        customExtractor: options.customExtractor || null,
        onDecision: options.onDecision || null,
        silent: options.silent || false
    };

    return async function antiAbuseMiddleware(req, res, next) {
        const startTime = Date.now();

        if (config.skipPaths.some(path => req.path.startsWith(path))) {
            return next();
        }

        const request = extractRequest(req, config);

        try {
            const decision = await engine.evaluate(request);

            req.riskDecision = decision;

            if (config.onDecision) {
                config.onDecision(decision, req, res);
            }

            if (!config.silent) {
                res.setHeader('X-Risk-Score', decision.riskScore.toFixed(3));
                res.setHeader('X-Risk-Level', decision.riskLevel);
            }

            switch (decision.action.type) {
                case 'ban':
                case 'block':
                    return handleBlock(res, decision, config);

                case 'throttle':
                    return handleThrottle(req, res, next, decision, config);

                case 'challenge':
                    if (!req.headers['x-challenge-response']) {
                        return handleChallenge(res, decision, config);
                    }
                    break;

                case 'allow':
                default:
                    break;
            }

            res.on('finish', () => {
                const responseTime = Date.now() - startTime;
                engine.recordEvent(decision.userId, {
                    ...request,
                    responseTime,
                    statusCode: res.statusCode
                });
            });

            next();
        } catch (error) {
            if (!config.silent) {
                console.error('[AntiAbuse] Error:', error.message);
            }
            next();
        }
    };

    function extractRequest(req, config) {
        if (config.customExtractor) {
            return config.customExtractor(req);
        }

        const ip = config.trustProxy 
            ? req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip
            : req.ip || req.connection?.remoteAddress;

        return {
            ip,
            userId: req.user?.id || req.session?.userId || ip,
            sessionId: req.session?.id || req.cookies?.sessionId,
            method: req.method,
            path: req.path,
            endpoint: `${req.method}:${req.path}`,
            action: req.path.split('/').filter(Boolean).pop() || 'root',
            headers: req.headers,
            body: req.body,
            query: req.query,
            client: extractClientInfo(req)
        };
    }

    function extractClientInfo(req) {
        return {
            timezone: req.headers['x-timezone'],
            timezoneOffset: req.headers['x-timezone-offset'],
            screenResolution: req.headers['x-screen-resolution'],
            colorDepth: req.headers['x-color-depth'],
            platform: req.headers['sec-ch-ua-platform'],
            mobile: req.headers['sec-ch-ua-mobile'] === '?1',
            touchSupport: req.headers['x-touch-support'] === 'true',
            cookiesEnabled: req.headers['x-cookies-enabled'] === 'true',
            localStorage: req.headers['x-local-storage'] === 'true'
        };
    }

    function handleBlock(res, decision, config) {
        res.status(config.blockStatusCode).json({
            error: 'Access Denied',
            reason: decision.action.reason,
            retryAfter: Math.ceil(decision.action.duration / 1000),
            requestId: decision.sessionId
        });
    }

    function handleThrottle(req, res, next, decision, config) {
        const delay = config.throttleDelay * (1 / decision.action.factor);
        
        res.setHeader('X-Throttle-Delay', delay);
        res.setHeader('Retry-After', Math.ceil(delay / 1000));

        setTimeout(() => {
            next();
        }, delay);
    }

    function handleChallenge(res, decision, config) {
        res.status(config.challengeStatusCode).json({
            error: 'Challenge Required',
            challengeType: decision.action.challengeType,
            challenge: generateChallenge(decision.action.challengeType),
            requestId: decision.sessionId
        });
    }

    function generateChallenge(type) {
        switch (type) {
            case 'proof_of_work':
                return {
                    type: 'proof_of_work',
                    difficulty: 4,
                    prefix: Math.random().toString(36).substring(2, 10),
                    algorithm: 'sha256'
                };

            case 'javascript_challenge':
                const a = Math.floor(Math.random() * 100);
                const b = Math.floor(Math.random() * 100);
                return {
                    type: 'javascript',
                    expression: `${a} + ${b}`,
                    expectedHash: simpleHash(`${a + b}`)
                };

            case 'captcha':
            default:
                return {
                    type: 'captcha',
                    provider: 'internal',
                    token: Math.random().toString(36).substring(2, 15)
                };
        }
    }

    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return hash.toString(16);
    }
}

function createRateLimitMiddleware(options = {}) {
    const engine = options.engine || new RiskEngine(options);

    return async function rateLimitMiddleware(req, res, next) {
        const ip = req.ip || req.connection?.remoteAddress;
        const identifier = req.user?.id || ip;
        const endpoint = `${req.method}:${req.path}`;

        const result = engine.rateLimiter.check(`${identifier}:${endpoint}`, {
            limit: options.limit,
            riskScore: req.riskDecision?.riskScore
        });

        res.setHeader('X-RateLimit-Limit', result.limit);
        res.setHeader('X-RateLimit-Remaining', result.remaining);
        res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetIn / 1000));

        if (!result.allowed) {
            res.setHeader('Retry-After', Math.ceil(result.retryAfter / 1000));
            return res.status(429).json({
                error: 'Too Many Requests',
                retryAfter: Math.ceil(result.retryAfter / 1000),
                limit: result.limit
            });
        }

        next();
    };
}

function createFingerprintMiddleware(options = {}) {
    const engine = options.engine || new RiskEngine(options);

    return async function fingerprintMiddleware(req, res, next) {
        const request = {
            ip: req.ip,
            headers: req.headers,
            client: {
                timezone: req.headers['x-timezone'],
                screenResolution: req.headers['x-screen-resolution'],
                platform: req.headers['sec-ch-ua-platform']
            }
        };

        const fingerprint = engine.fingerprinter.generate(request);
        
        req.fingerprint = fingerprint;
        
        res.setHeader('X-Fingerprint', fingerprint.fingerprint.substring(0, 8));

        if (fingerprint.isBot?.isBot) {
            req.isBot = true;
        }

        next();
    };
}

export {
    createAntiAbuseMiddleware,
    createRateLimitMiddleware,
    createFingerprintMiddleware
};

export default createAntiAbuseMiddleware;
