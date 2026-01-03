import MathUtils from '../utils/MathUtils.js';
import MemoryStore from '../storage/MemoryStore.js';
import BehaviorAnalyzer from './BehaviorAnalyzer.js';
import PatternDetector from './PatternDetector.js';
import RateLimiter from './RateLimiter.js';
import Fingerprinter from './Fingerprinter.js';

class RiskEngine {
    constructor(options = {}) {
        this.store = options.store || new MemoryStore({ maxSize: 50000, ttl: 3600000 });
        this.behaviorAnalyzer = new BehaviorAnalyzer(options.behavior || {});
        this.patternDetector = new PatternDetector(options.patterns || {});
        this.rateLimiter = new RateLimiter(options.rateLimit || {});
        this.fingerprinter = new Fingerprinter(options.fingerprint || {});

        this.thresholds = {
            low: options.thresholds?.low || 0.3,
            medium: options.thresholds?.medium || 0.5,
            high: options.thresholds?.high || 0.7,
            critical: options.thresholds?.critical || 0.9
        };

        this.weights = {
            behavior: options.weights?.behavior || 0.25,
            patterns: options.weights?.patterns || 0.25,
            rateLimit: options.weights?.rateLimit || 0.2,
            fingerprint: options.weights?.fingerprint || 0.15,
            reputation: options.weights?.reputation || 0.15
        };

        this.actions = {
            allow: { maxScore: this.thresholds.low },
            challenge: { minScore: this.thresholds.low, maxScore: this.thresholds.medium },
            throttle: { minScore: this.thresholds.medium, maxScore: this.thresholds.high },
            block: { minScore: this.thresholds.high, maxScore: this.thresholds.critical },
            ban: { minScore: this.thresholds.critical }
        };

        this.hooks = {
            onHighRisk: options.onHighRisk || null,
            onBlock: options.onBlock || null,
            onAnomaly: options.onAnomaly || null
        };

        this.globalStats = {
            totalEvaluations: 0,
            blocked: 0,
            challenged: 0,
            allowed: 0,
            avgRiskScore: 0
        };
    }

    async evaluate(request) {
        const startTime = Date.now();
        const userId = this.extractUserId(request);
        const sessionId = request.sessionId || this.generateSessionId(request);

        this.recordEvent(userId, request);

        const [
            behaviorResult,
            patternResult,
            rateLimitResult,
            fingerprintResult,
            reputationResult
        ] = await Promise.all([
            this.analyzeBehavior(userId),
            this.analyzePatterns(userId),
            this.checkRateLimit(userId, request),
            this.analyzeFingerprint(request),
            this.getReputation(userId)
        ]);

        const riskScore = this.calculateRiskScore({
            behavior: behaviorResult,
            patterns: patternResult,
            rateLimit: rateLimitResult,
            fingerprint: fingerprintResult,
            reputation: reputationResult
        });

        const action = this.determineAction(riskScore, {
            behavior: behaviorResult,
            patterns: patternResult,
            rateLimit: rateLimitResult,
            fingerprint: fingerprintResult
        });

        const decision = {
            userId,
            sessionId,
            riskScore,
            riskLevel: this.getRiskLevel(riskScore),
            action,
            allowed: action.type === 'allow' || action.type === 'challenge',
            components: {
                behavior: {
                    score: behaviorResult.riskScore,
                    factors: behaviorResult.factors
                },
                patterns: {
                    score: patternResult.riskScore,
                    attackType: patternResult.attackType
                },
                rateLimit: {
                    allowed: rateLimitResult.allowed,
                    remaining: rateLimitResult.remaining
                },
                fingerprint: {
                    score: fingerprintResult.anomalyScore?.score || 0,
                    isBot: fingerprintResult.isBot?.isBot || false,
                    fingerprint: fingerprintResult.fingerprint
                },
                reputation: {
                    score: reputationResult.score,
                    history: reputationResult.history
                }
            },
            metadata: {
                evaluationTime: Date.now() - startTime,
                timestamp: Date.now()
            }
        };

        this.updateStats(decision);
        this.updateReputation(userId, decision);
        this.triggerHooks(decision);

        return decision;
    }

    extractUserId(request) {
        return request.userId || 
               request.user?.id || 
               request.headers?.['x-user-id'] ||
               request.ip ||
               'anonymous';
    }

    generateSessionId(request) {
        const components = [
            request.ip,
            request.headers?.['user-agent'],
            Date.now().toString(36)
        ].filter(Boolean).join('|');
        
        return this.hash(components);
    }

    hash(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) + hash) + str.charCodeAt(i);
        }
        return (hash >>> 0).toString(16);
    }

    recordEvent(userId, request) {
        const eventKey = `events:${userId}`;
        const event = {
            timestamp: Date.now(),
            action: request.action || request.method,
            endpoint: request.endpoint || request.path || request.url,
            ip: request.ip,
            userAgent: request.headers?.['user-agent'],
            responseTime: request.responseTime,
            payloadSize: request.body ? JSON.stringify(request.body).length : 0,
            statusCode: request.statusCode,
            method: request.method
        };

        this.store.push(eventKey, event, 1000);
    }

    async analyzeBehavior(userId) {
        const events = this.store.get(`events:${userId}`) || [];
        return this.behaviorAnalyzer.analyze(userId, events);
    }

    async analyzePatterns(userId) {
        const events = this.store.get(`events:${userId}`) || [];
        return this.patternDetector.detect(events);
    }

    async checkRateLimit(userId, request) {
        const identifier = `${userId}:${request.endpoint || request.path || 'default'}`;
        const reputation = await this.getReputation(userId);
        
        return this.rateLimiter.check(identifier, {
            riskScore: reputation.score
        });
    }

    async analyzeFingerprint(request) {
        return this.fingerprinter.generate(request);
    }

    async getReputation(userId) {
        const reputationKey = `reputation:${userId}`;
        const reputation = this.store.get(reputationKey);

        if (!reputation) {
            return {
                score: 0,
                history: [],
                firstSeen: Date.now(),
                totalRequests: 0,
                blockedRequests: 0
            };
        }

        return reputation;
    }

    calculateRiskScore(components) {
        let weightedSum = 0;
        let totalWeight = 0;

        if (components.behavior?.reliable) {
            weightedSum += components.behavior.riskScore * this.weights.behavior;
            totalWeight += this.weights.behavior;
        }

        if (components.patterns) {
            weightedSum += components.patterns.riskScore * this.weights.patterns;
            totalWeight += this.weights.patterns;
        }

        if (components.rateLimit) {
            const rateLimitScore = components.rateLimit.allowed ? 0 : 
                (components.rateLimit.severity || 0.5);
            weightedSum += rateLimitScore * this.weights.rateLimit;
            totalWeight += this.weights.rateLimit;
        }

        if (components.fingerprint) {
            const fpScore = Math.max(
                components.fingerprint.anomalyScore?.score || 0,
                components.fingerprint.isBot?.score || 0,
                components.fingerprint.isSuspicious?.suspicious ? 0.7 : 0
            );
            weightedSum += fpScore * this.weights.fingerprint;
            totalWeight += this.weights.fingerprint;
        }

        if (components.reputation) {
            weightedSum += components.reputation.score * this.weights.reputation;
            totalWeight += this.weights.reputation;
        }

        if (totalWeight === 0) return 0;

        let baseScore = weightedSum / totalWeight;

        if (components.patterns?.attackType) {
            baseScore = Math.max(baseScore, 0.6);
        }

        if (components.fingerprint?.isBot?.isBot) {
            baseScore = Math.max(baseScore, 0.7);
        }

        if (!components.rateLimit?.allowed) {
            baseScore = Math.max(baseScore, 0.5);
        }

        return MathUtils.clamp(baseScore, 0, 1);
    }

    getRiskLevel(score) {
        if (score >= this.thresholds.critical) return 'critical';
        if (score >= this.thresholds.high) return 'high';
        if (score >= this.thresholds.medium) return 'medium';
        if (score >= this.thresholds.low) return 'low';
        return 'minimal';
    }

    determineAction(riskScore, components) {
        if (riskScore >= this.thresholds.critical) {
            return {
                type: 'ban',
                duration: 86400000,
                reason: 'critical_risk_level'
            };
        }

        if (riskScore >= this.thresholds.high) {
            return {
                type: 'block',
                duration: 3600000,
                reason: this.getBlockReason(components)
            };
        }

        if (riskScore >= this.thresholds.medium) {
            return {
                type: 'throttle',
                factor: 0.5,
                reason: 'elevated_risk'
            };
        }

        if (riskScore >= this.thresholds.low) {
            return {
                type: 'challenge',
                challengeType: this.selectChallenge(components),
                reason: 'suspicious_activity'
            };
        }

        return {
            type: 'allow',
            reason: 'low_risk'
        };
    }

    getBlockReason(components) {
        if (components.patterns?.attackType) {
            return `detected_${components.patterns.attackType}`;
        }
        if (components.fingerprint?.isBot?.isBot) {
            return 'bot_detected';
        }
        if (!components.rateLimit?.allowed) {
            return 'rate_limit_exceeded';
        }
        return 'high_risk_score';
    }

    selectChallenge(components) {
        if (components.fingerprint?.isBot?.score > 0.5) {
            return 'captcha';
        }
        if (components.behavior?.metrics?.automationScore > 0.5) {
            return 'proof_of_work';
        }
        return 'javascript_challenge';
    }

    updateStats(decision) {
        this.globalStats.totalEvaluations++;
        
        if (decision.action.type === 'block' || decision.action.type === 'ban') {
            this.globalStats.blocked++;
        } else if (decision.action.type === 'challenge') {
            this.globalStats.challenged++;
        } else {
            this.globalStats.allowed++;
        }

        const n = this.globalStats.totalEvaluations;
        this.globalStats.avgRiskScore = 
            ((n - 1) * this.globalStats.avgRiskScore + decision.riskScore) / n;
    }

    updateReputation(userId, decision) {
        const reputationKey = `reputation:${userId}`;
        let reputation = this.store.get(reputationKey) || {
            score: 0,
            history: [],
            firstSeen: Date.now(),
            totalRequests: 0,
            blockedRequests: 0
        };

        reputation.totalRequests++;
        
        if (!decision.allowed) {
            reputation.blockedRequests++;
        }

        reputation.history.push({
            timestamp: Date.now(),
            riskScore: decision.riskScore,
            action: decision.action.type
        });

        if (reputation.history.length > 100) {
            reputation.history = reputation.history.slice(-100);
        }

        const recentScores = reputation.history.slice(-20).map(h => h.riskScore);
        const decayedScore = MathUtils.exponentialMovingAverage(recentScores, 0.3);
        const blockRatio = reputation.blockedRequests / reputation.totalRequests;
        
        reputation.score = MathUtils.clamp(
            decayedScore * 0.7 + blockRatio * 0.3,
            0, 1
        );

        this.store.set(reputationKey, reputation);
    }

    triggerHooks(decision) {
        if (decision.riskScore >= this.thresholds.high && this.hooks.onHighRisk) {
            try {
                this.hooks.onHighRisk(decision);
            } catch (e) {}
        }

        if ((decision.action.type === 'block' || decision.action.type === 'ban') && this.hooks.onBlock) {
            try {
                this.hooks.onBlock(decision);
            } catch (e) {}
        }

        if (decision.components.behavior?.factors?.length > 0 && this.hooks.onAnomaly) {
            try {
                this.hooks.onAnomaly(decision);
            } catch (e) {}
        }
    }

    setThresholds(thresholds) {
        Object.assign(this.thresholds, thresholds);
        this.actions = {
            allow: { maxScore: this.thresholds.low },
            challenge: { minScore: this.thresholds.low, maxScore: this.thresholds.medium },
            throttle: { minScore: this.thresholds.medium, maxScore: this.thresholds.high },
            block: { minScore: this.thresholds.high, maxScore: this.thresholds.critical },
            ban: { minScore: this.thresholds.critical }
        };
    }

    setWeights(weights) {
        Object.assign(this.weights, weights);
    }

    setHook(hookName, callback) {
        if (this.hooks.hasOwnProperty(hookName)) {
            this.hooks[hookName] = callback;
        }
    }

    getStats() {
        return {
            ...this.globalStats,
            blockRate: this.globalStats.totalEvaluations > 0 
                ? this.globalStats.blocked / this.globalStats.totalEvaluations 
                : 0,
            challengeRate: this.globalStats.totalEvaluations > 0
                ? this.globalStats.challenged / this.globalStats.totalEvaluations
                : 0,
            rateLimiter: this.rateLimiter.getGlobalMetrics(),
            fingerprinter: this.fingerprinter.getStats(),
            store: this.store.getStats()
        };
    }

    async getUserProfile(userId) {
        const events = this.store.get(`events:${userId}`) || [];
        const reputation = await this.getReputation(userId);
        const behaviorProfile = this.behaviorAnalyzer.getProfile(userId);
        const rateLimitStatus = this.rateLimiter.getStatus(userId);

        return {
            userId,
            reputation,
            eventCount: events.length,
            lastActivity: events.length > 0 ? events[events.length - 1].timestamp : null,
            behaviorProfile: behaviorProfile ? {
                confidence: behaviorProfile.confidence,
                lastUpdated: behaviorProfile.lastUpdated
            } : null,
            rateLimitStatus
        };
    }

    resetUser(userId) {
        this.store.delete(`events:${userId}`);
        this.store.delete(`reputation:${userId}`);
        this.behaviorAnalyzer.clearProfile(userId);
        this.rateLimiter.reset(userId);
    }

    exportConfig() {
        return {
            thresholds: this.thresholds,
            weights: this.weights,
            actions: this.actions
        };
    }

    importConfig(config) {
        if (config.thresholds) this.setThresholds(config.thresholds);
        if (config.weights) this.setWeights(config.weights);
    }

    destroy() {
        this.store.destroy();
        this.rateLimiter.destroy();
    }
}

export default RiskEngine;
