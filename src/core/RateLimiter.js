import MathUtils from '../utils/MathUtils.js';

class RateLimiter {
    constructor(options = {}) {
        this.defaultLimit = options.defaultLimit || 100;
        this.windowSize = options.windowSize || 60000;
        this.burstMultiplier = options.burstMultiplier || 2;
        this.adaptiveEnabled = options.adaptiveEnabled !== false;
        this.penaltyDecay = options.penaltyDecay || 0.95;
        this.rewardRate = options.rewardRate || 1.05;
        
        this.buckets = new Map();
        this.userLimits = new Map();
        this.penalties = new Map();
        this.history = new Map();
        this.globalMetrics = {
            totalRequests: 0,
            blockedRequests: 0,
            avgRequestRate: 0,
            peakRate: 0
        };

        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    }

    check(identifier, options = {}) {
        const now = Date.now();
        const bucket = this.getOrCreateBucket(identifier);
        const limit = this.getEffectiveLimit(identifier, options);
        
        this.pruneOldRequests(bucket, now);
        
        const currentCount = bucket.requests.length;
        const burstLimit = Math.floor(limit * this.burstMultiplier);

        this.updateHistory(identifier, currentCount, limit);
        this.globalMetrics.totalRequests++;

        if (currentCount >= limit) {
            const severity = this.calculateSeverity(currentCount, limit, burstLimit);
            this.applyPenalty(identifier, severity);
            this.globalMetrics.blockedRequests++;
            
            return {
                allowed: false,
                remaining: 0,
                resetIn: this.getResetTime(bucket, now),
                limit,
                currentCount,
                severity,
                reason: currentCount >= burstLimit ? 'burst_exceeded' : 'rate_exceeded',
                retryAfter: this.calculateRetryAfter(identifier, severity)
            };
        }

        bucket.requests.push(now);
        bucket.lastAccess = now;

        if (this.adaptiveEnabled && currentCount < limit * 0.5) {
            this.applyReward(identifier);
        }

        return {
            allowed: true,
            remaining: limit - currentCount - 1,
            resetIn: this.getResetTime(bucket, now),
            limit,
            currentCount: currentCount + 1
        };
    }

    getOrCreateBucket(identifier) {
        if (!this.buckets.has(identifier)) {
            this.buckets.set(identifier, {
                requests: [],
                createdAt: Date.now(),
                lastAccess: Date.now(),
                violations: 0
            });
        }
        return this.buckets.get(identifier);
    }

    pruneOldRequests(bucket, now) {
        const cutoff = now - this.windowSize;
        bucket.requests = bucket.requests.filter(ts => ts > cutoff);
    }

    getEffectiveLimit(identifier, options = {}) {
        let baseLimit = options.limit || this.userLimits.get(identifier) || this.defaultLimit;
        
        const penalty = this.penalties.get(identifier) || 1;
        const adjustedLimit = Math.floor(baseLimit / penalty);
        
        if (options.riskScore) {
            const riskMultiplier = 1 - (options.riskScore * 0.7);
            return Math.max(1, Math.floor(adjustedLimit * riskMultiplier));
        }

        return Math.max(1, adjustedLimit);
    }

    calculateSeverity(current, limit, burstLimit) {
        if (current >= burstLimit) {
            return 1;
        }
        return (current - limit) / (burstLimit - limit);
    }

    applyPenalty(identifier, severity) {
        const currentPenalty = this.penalties.get(identifier) || 1;
        const newPenalty = Math.min(currentPenalty * (1 + severity * 0.5), 10);
        this.penalties.set(identifier, newPenalty);

        const bucket = this.buckets.get(identifier);
        if (bucket) {
            bucket.violations++;
        }
    }

    applyReward(identifier) {
        const currentPenalty = this.penalties.get(identifier);
        if (currentPenalty && currentPenalty > 1) {
            const newPenalty = Math.max(currentPenalty * this.penaltyDecay, 1);
            if (newPenalty <= 1.01) {
                this.penalties.delete(identifier);
            } else {
                this.penalties.set(identifier, newPenalty);
            }
        }
    }

    getResetTime(bucket, now) {
        if (bucket.requests.length === 0) {
            return 0;
        }
        const oldestRequest = Math.min(...bucket.requests);
        return Math.max(0, (oldestRequest + this.windowSize) - now);
    }

    calculateRetryAfter(identifier, severity) {
        const baseDelay = this.windowSize / 10;
        const penaltyMultiplier = this.penalties.get(identifier) || 1;
        return Math.floor(baseDelay * severity * penaltyMultiplier);
    }

    updateHistory(identifier, count, limit) {
        if (!this.history.has(identifier)) {
            this.history.set(identifier, {
                samples: [],
                maxCount: 0,
                totalSamples: 0
            });
        }

        const history = this.history.get(identifier);
        history.samples.push({ count, limit, timestamp: Date.now() });
        history.maxCount = Math.max(history.maxCount, count);
        history.totalSamples++;

        if (history.samples.length > 1000) {
            history.samples = history.samples.slice(-500);
        }
    }

    setUserLimit(identifier, limit) {
        this.userLimits.set(identifier, limit);
    }

    getUserLimit(identifier) {
        return this.userLimits.get(identifier) || this.defaultLimit;
    }

    getStatus(identifier) {
        const bucket = this.buckets.get(identifier);
        const penalty = this.penalties.get(identifier) || 1;
        const history = this.history.get(identifier);
        const limit = this.getEffectiveLimit(identifier);

        if (!bucket) {
            return {
                exists: false,
                currentCount: 0,
                limit,
                penalty: 1,
                violations: 0
            };
        }

        const now = Date.now();
        this.pruneOldRequests(bucket, now);

        return {
            exists: true,
            currentCount: bucket.requests.length,
            limit,
            effectiveLimit: this.getEffectiveLimit(identifier),
            penalty,
            violations: bucket.violations,
            lastAccess: bucket.lastAccess,
            resetIn: this.getResetTime(bucket, now),
            history: history ? {
                maxCount: history.maxCount,
                totalSamples: history.totalSamples,
                recentAvg: this.calculateRecentAverage(history)
            } : null
        };
    }

    calculateRecentAverage(history) {
        if (!history || history.samples.length === 0) return 0;
        const recent = history.samples.slice(-100);
        return MathUtils.mean(recent.map(s => s.count));
    }

    slidingWindowLog(identifier, options = {}) {
        const now = Date.now();
        const bucket = this.getOrCreateBucket(identifier);
        const limit = this.getEffectiveLimit(identifier, options);

        const windowStart = now - this.windowSize;
        let weightedCount = 0;

        for (const ts of bucket.requests) {
            if (ts > windowStart) {
                const age = now - ts;
                const weight = 1 - (age / this.windowSize);
                weightedCount += weight;
            }
        }

        if (weightedCount >= limit) {
            return { allowed: false, weightedCount, limit };
        }

        bucket.requests.push(now);
        return { allowed: true, weightedCount: weightedCount + 1, limit };
    }

    tokenBucket(identifier, options = {}) {
        const now = Date.now();
        const limit = options.limit || this.defaultLimit;
        const refillRate = options.refillRate || limit / (this.windowSize / 1000);

        let tokenBucket = this.buckets.get(`token:${identifier}`);
        
        if (!tokenBucket) {
            tokenBucket = {
                tokens: limit,
                lastRefill: now
            };
            this.buckets.set(`token:${identifier}`, tokenBucket);
        }

        const elapsed = (now - tokenBucket.lastRefill) / 1000;
        const refill = elapsed * refillRate;
        tokenBucket.tokens = Math.min(limit, tokenBucket.tokens + refill);
        tokenBucket.lastRefill = now;

        const cost = options.cost || 1;

        if (tokenBucket.tokens >= cost) {
            tokenBucket.tokens -= cost;
            return {
                allowed: true,
                remainingTokens: tokenBucket.tokens,
                limit
            };
        }

        const waitTime = (cost - tokenBucket.tokens) / refillRate * 1000;
        
        return {
            allowed: false,
            remainingTokens: tokenBucket.tokens,
            limit,
            retryAfter: Math.ceil(waitTime)
        };
    }

    leakyBucket(identifier, options = {}) {
        const now = Date.now();
        const capacity = options.capacity || this.defaultLimit;
        const leakRate = options.leakRate || capacity / (this.windowSize / 1000);

        let leakyBucket = this.buckets.get(`leaky:${identifier}`);

        if (!leakyBucket) {
            leakyBucket = {
                water: 0,
                lastLeak: now
            };
            this.buckets.set(`leaky:${identifier}`, leakyBucket);
        }

        const elapsed = (now - leakyBucket.lastLeak) / 1000;
        const leaked = elapsed * leakRate;
        leakyBucket.water = Math.max(0, leakyBucket.water - leaked);
        leakyBucket.lastLeak = now;

        const amount = options.amount || 1;

        if (leakyBucket.water + amount <= capacity) {
            leakyBucket.water += amount;
            return {
                allowed: true,
                currentLevel: leakyBucket.water,
                capacity
            };
        }

        return {
            allowed: false,
            currentLevel: leakyBucket.water,
            capacity,
            overflow: leakyBucket.water + amount - capacity
        };
    }

    adaptiveLimit(identifier, metrics) {
        const history = this.history.get(identifier);
        if (!history || history.samples.length < 50) {
            return this.defaultLimit;
        }

        const recent = history.samples.slice(-100);
        const avgUsage = MathUtils.mean(recent.map(s => s.count / s.limit));
        const peakUsage = Math.max(...recent.map(s => s.count / s.limit));

        let newLimit = this.defaultLimit;

        if (avgUsage < 0.3 && peakUsage < 0.5) {
            newLimit = Math.floor(this.defaultLimit * 1.2);
        } else if (avgUsage > 0.8 || peakUsage > 0.95) {
            newLimit = Math.floor(this.defaultLimit * 0.8);
        }

        if (metrics?.riskScore > 0.5) {
            newLimit = Math.floor(newLimit * (1 - metrics.riskScore * 0.5));
        }

        newLimit = MathUtils.clamp(newLimit, Math.floor(this.defaultLimit * 0.1), this.defaultLimit * 3);

        this.userLimits.set(identifier, newLimit);
        return newLimit;
    }

    cleanup() {
        const now = Date.now();
        const staleThreshold = this.windowSize * 10;

        for (const [key, bucket] of this.buckets.entries()) {
            if (now - bucket.lastAccess > staleThreshold) {
                this.buckets.delete(key);
                this.penalties.delete(key);
                this.history.delete(key);
                this.userLimits.delete(key);
            }
        }
    }

    reset(identifier) {
        this.buckets.delete(identifier);
        this.buckets.delete(`token:${identifier}`);
        this.buckets.delete(`leaky:${identifier}`);
        this.penalties.delete(identifier);
        this.history.delete(identifier);
    }

    resetAll() {
        this.buckets.clear();
        this.penalties.clear();
        this.history.clear();
        this.userLimits.clear();
    }

    getGlobalMetrics() {
        return {
            ...this.globalMetrics,
            activeBuckets: this.buckets.size,
            usersWithPenalties: this.penalties.size,
            blockRate: this.globalMetrics.totalRequests > 0 
                ? this.globalMetrics.blockedRequests / this.globalMetrics.totalRequests 
                : 0
        };
    }

    destroy() {
        clearInterval(this.cleanupInterval);
        this.resetAll();
    }
}

export default RateLimiter;
