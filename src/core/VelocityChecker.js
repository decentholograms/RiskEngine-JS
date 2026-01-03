class VelocityChecker {
    constructor(options = {}) {
        this.windows = new Map();
        this.rules = new Map();
        this.violations = new Map();
        this.defaultWindows = [60000, 300000, 3600000, 86400000];
        
        this.initializeDefaultRules();
    }

    initializeDefaultRules() {
        this.addRule('login_attempts', {
            windows: {
                60000: 5,
                300000: 15,
                3600000: 50
            },
            action: 'block',
            cooldown: 900000
        });

        this.addRule('password_resets', {
            windows: {
                3600000: 3,
                86400000: 10
            },
            action: 'block',
            cooldown: 3600000
        });

        this.addRule('api_calls', {
            windows: {
                60000: 100,
                300000: 400,
                3600000: 2000
            },
            action: 'throttle',
            cooldown: 60000
        });

        this.addRule('account_creation', {
            windows: {
                3600000: 3,
                86400000: 10
            },
            action: 'block',
            cooldown: 86400000
        });

        this.addRule('payment_attempts', {
            windows: {
                60000: 3,
                300000: 10,
                3600000: 30
            },
            action: 'block',
            cooldown: 3600000
        });

        this.addRule('search_queries', {
            windows: {
                60000: 30,
                300000: 100
            },
            action: 'throttle',
            cooldown: 60000
        });

        this.addRule('file_uploads', {
            windows: {
                60000: 10,
                300000: 30,
                3600000: 100
            },
            action: 'block',
            cooldown: 300000
        });

        this.addRule('message_sends', {
            windows: {
                60000: 20,
                300000: 60,
                3600000: 200
            },
            action: 'throttle',
            cooldown: 60000
        });
    }

    addRule(name, config) {
        this.rules.set(name, {
            name,
            windows: config.windows || {},
            action: config.action || 'block',
            cooldown: config.cooldown || 300000,
            multiplier: config.multiplier || 1,
            exemptRoles: config.exemptRoles || [],
            enabled: config.enabled !== false
        });
    }

    removeRule(name) {
        this.rules.delete(name);
    }

    getRule(name) {
        return this.rules.get(name);
    }

    check(identifier, ruleName, options = {}) {
        const rule = this.rules.get(ruleName);
        
        if (!rule || !rule.enabled) {
            return { allowed: true, reason: 'rule_not_found_or_disabled' };
        }

        if (options.role && rule.exemptRoles.includes(options.role)) {
            return { allowed: true, reason: 'exempt_role' };
        }

        const violation = this.getActiveViolation(identifier, ruleName);
        if (violation) {
            return {
                allowed: false,
                reason: 'active_violation',
                violation,
                retryAfter: violation.expiresAt - Date.now()
            };
        }

        const key = `${identifier}:${ruleName}`;
        const now = Date.now();
        
        if (!this.windows.has(key)) {
            this.windows.set(key, []);
        }

        const events = this.windows.get(key);
        
        events.push(now);

        const result = this.evaluateWindows(events, rule, now);

        if (!result.allowed) {
            this.recordViolation(identifier, ruleName, result, rule);
        }

        this.pruneEvents(key, now);

        return result;
    }

    evaluateWindows(events, rule, now) {
        const violations = [];
        let worstViolation = null;

        for (const [windowMs, limit] of Object.entries(rule.windows)) {
            const windowStart = now - parseInt(windowMs);
            const count = events.filter(ts => ts > windowStart).length;
            const adjustedLimit = Math.floor(limit * rule.multiplier);

            if (count > adjustedLimit) {
                const violation = {
                    window: parseInt(windowMs),
                    limit: adjustedLimit,
                    count,
                    excess: count - adjustedLimit,
                    severity: (count - adjustedLimit) / adjustedLimit
                };
                
                violations.push(violation);
                
                if (!worstViolation || violation.severity > worstViolation.severity) {
                    worstViolation = violation;
                }
            }
        }

        if (violations.length === 0) {
            const counts = {};
            for (const [windowMs, limit] of Object.entries(rule.windows)) {
                const windowStart = now - parseInt(windowMs);
                const count = events.filter(ts => ts > windowStart).length;
                counts[windowMs] = { count, limit: Math.floor(limit * rule.multiplier) };
            }

            return {
                allowed: true,
                counts,
                nearLimit: Object.values(counts).some(c => c.count > c.limit * 0.8)
            };
        }

        return {
            allowed: false,
            reason: 'velocity_exceeded',
            action: rule.action,
            violations,
            worstViolation
        };
    }

    recordViolation(identifier, ruleName, result, rule) {
        const key = `${identifier}:${ruleName}`;
        const now = Date.now();

        const existingViolations = this.violations.get(key) || [];
        
        const violation = {
            timestamp: now,
            expiresAt: now + rule.cooldown,
            severity: result.worstViolation?.severity || 0.5,
            details: result.violations
        };

        existingViolations.push(violation);

        if (existingViolations.length > 100) {
            existingViolations.splice(0, existingViolations.length - 100);
        }

        this.violations.set(key, existingViolations);
    }

    getActiveViolation(identifier, ruleName) {
        const key = `${identifier}:${ruleName}`;
        const violations = this.violations.get(key);
        
        if (!violations || violations.length === 0) return null;

        const now = Date.now();
        const active = violations.find(v => v.expiresAt > now);
        
        return active || null;
    }

    pruneEvents(key, now) {
        const events = this.windows.get(key);
        if (!events) return;

        const maxWindow = 86400000;
        const cutoff = now - maxWindow;
        
        const pruned = events.filter(ts => ts > cutoff);
        this.windows.set(key, pruned);
    }

    getVelocityStats(identifier, ruleName) {
        const key = `${identifier}:${ruleName}`;
        const events = this.windows.get(key) || [];
        const violations = this.violations.get(key) || [];
        const rule = this.rules.get(ruleName);

        if (!rule) return null;

        const now = Date.now();
        const stats = {
            identifier,
            ruleName,
            windowCounts: {},
            totalEvents: events.length,
            recentViolations: violations.filter(v => now - v.timestamp < 86400000).length,
            activeViolation: this.getActiveViolation(identifier, ruleName)
        };

        for (const [windowMs, limit] of Object.entries(rule.windows)) {
            const windowStart = now - parseInt(windowMs);
            const count = events.filter(ts => ts > windowStart).length;
            stats.windowCounts[windowMs] = {
                count,
                limit: Math.floor(limit * rule.multiplier),
                percentage: count / Math.floor(limit * rule.multiplier) * 100
            };
        }

        return stats;
    }

    reset(identifier, ruleName = null) {
        if (ruleName) {
            const key = `${identifier}:${ruleName}`;
            this.windows.delete(key);
            this.violations.delete(key);
        } else {
            for (const [key] of this.windows.entries()) {
                if (key.startsWith(`${identifier}:`)) {
                    this.windows.delete(key);
                }
            }
            for (const [key] of this.violations.entries()) {
                if (key.startsWith(`${identifier}:`)) {
                    this.violations.delete(key);
                }
            }
        }
    }

    adjustMultiplier(ruleName, multiplier) {
        const rule = this.rules.get(ruleName);
        if (rule) {
            rule.multiplier = multiplier;
        }
    }

    batchCheck(identifier, ruleNames) {
        const results = {};
        
        for (const ruleName of ruleNames) {
            results[ruleName] = this.check(identifier, ruleName);
        }

        const blocked = Object.entries(results).filter(([_, r]) => !r.allowed);
        
        return {
            results,
            allAllowed: blocked.length === 0,
            blockedBy: blocked.map(([name]) => name)
        };
    }

    getGlobalStats() {
        const now = Date.now();
        let totalEvents = 0;
        let activeViolations = 0;
        const ruleStats = {};

        for (const [key, events] of this.windows.entries()) {
            totalEvents += events.length;
            const ruleName = key.split(':')[1];
            ruleStats[ruleName] = (ruleStats[ruleName] || 0) + events.length;
        }

        for (const violations of this.violations.values()) {
            activeViolations += violations.filter(v => v.expiresAt > now).length;
        }

        return {
            totalTrackedEvents: totalEvents,
            activeViolations,
            uniqueIdentifiers: new Set(
                Array.from(this.windows.keys()).map(k => k.split(':')[0])
            ).size,
            ruleStats,
            rules: Array.from(this.rules.keys())
        };
    }

    cleanup() {
        const now = Date.now();
        const maxAge = 86400000;

        for (const [key, events] of this.windows.entries()) {
            const recent = events.filter(ts => now - ts < maxAge);
            if (recent.length === 0) {
                this.windows.delete(key);
            } else {
                this.windows.set(key, recent);
            }
        }

        for (const [key, violations] of this.violations.entries()) {
            const recent = violations.filter(v => now - v.timestamp < maxAge * 7);
            if (recent.length === 0) {
                this.violations.delete(key);
            } else {
                this.violations.set(key, recent);
            }
        }
    }

    exportRules() {
        const rules = {};
        for (const [name, rule] of this.rules.entries()) {
            rules[name] = { ...rule };
        }
        return rules;
    }

    importRules(rules) {
        for (const [name, config] of Object.entries(rules)) {
            this.addRule(name, config);
        }
    }
}

export default VelocityChecker;
