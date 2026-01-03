class ThreatIntelligence {
    constructor(options = {}) {
        this.ipReputation = new Map();
        this.userAgentBlacklist = new Set();
        this.suspiciousPatterns = new Set();
        this.geoRisk = new Map();
        this.asnRisk = new Map();
        this.threatFeeds = new Map();
        this.cacheTimeout = options.cacheTimeout || 3600000;
        this.lastUpdate = new Map();

        this.initializeDefaults();
    }

    initializeDefaults() {
        this.addBotUserAgents([
            'python-requests',
            'python-urllib',
            'curl/',
            'wget/',
            'scrapy',
            'httpclient',
            'java/',
            'apache-httpclient',
            'go-http-client',
            'axios/',
            'node-fetch',
            'libwww-perl',
            'mechanize',
            'phantom',
            'selenium',
            'headless',
            'crawler',
            'spider',
            'scraper',
            'bot'
        ]);

        this.addSuspiciousPatterns([
            /union\s+select/i,
            /select\s+.*\s+from/i,
            /<script[^>]*>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /\.\.\//,
            /\/etc\/passwd/i,
            /cmd\.exe/i,
            /powershell/i,
            /eval\s*\(/i,
            /base64_decode/i,
            /\$\{.*\}/,
            /\{\{.*\}\}/
        ]);

        this.setGeoRisk({
            'XX': 0.8,
            'A1': 0.9,
            'A2': 0.9
        });

        this.setASNRisk({
            'DIGITALOCEAN': 0.4,
            'AWS': 0.3,
            'GOOGLE-CLOUD': 0.3,
            'AZURE': 0.3,
            'LINODE': 0.4,
            'VULTR': 0.4,
            'OVH': 0.4,
            'HETZNER': 0.4
        });
    }

    addBotUserAgents(agents) {
        for (const agent of agents) {
            this.userAgentBlacklist.add(agent.toLowerCase());
        }
    }

    addSuspiciousPatterns(patterns) {
        for (const pattern of patterns) {
            this.suspiciousPatterns.add(pattern);
        }
    }

    setGeoRisk(geoRiskMap) {
        for (const [country, risk] of Object.entries(geoRiskMap)) {
            this.geoRisk.set(country.toUpperCase(), risk);
        }
    }

    setASNRisk(asnRiskMap) {
        for (const [asn, risk] of Object.entries(asnRiskMap)) {
            this.asnRisk.set(asn.toUpperCase(), risk);
        }
    }

    async analyze(request) {
        const results = {
            ip: await this.analyzeIP(request.ip),
            userAgent: this.analyzeUserAgent(request.headers?.['user-agent']),
            payload: this.analyzePayload(request),
            geo: this.analyzeGeo(request.geo),
            asn: this.analyzeASN(request.asn),
            referrer: this.analyzeReferrer(request.headers?.referer),
            headers: this.analyzeHeaders(request.headers)
        };

        const riskScore = this.calculateOverallRisk(results);

        return {
            ...results,
            overallRisk: riskScore,
            threats: this.identifyThreats(results),
            recommendation: this.getRecommendation(riskScore, results)
        };
    }

    async analyzeIP(ip) {
        if (!ip) return { risk: 0, reason: 'no_ip' };

        const cached = this.ipReputation.get(ip);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        const result = {
            risk: 0,
            reasons: [],
            type: 'unknown'
        };

        if (this.isPrivateIP(ip)) {
            result.type = 'private';
            result.risk = 0;
        } else if (this.isDatacenterIP(ip)) {
            result.type = 'datacenter';
            result.risk = 0.4;
            result.reasons.push('datacenter_ip');
        } else if (this.isTorExitNode(ip)) {
            result.type = 'tor';
            result.risk = 0.8;
            result.reasons.push('tor_exit_node');
        } else if (this.isVPN(ip)) {
            result.type = 'vpn';
            result.risk = 0.5;
            result.reasons.push('vpn_detected');
        } else {
            result.type = 'residential';
        }

        const reputation = this.getIPReputation(ip);
        if (reputation.blocked > 0) {
            result.risk = Math.max(result.risk, reputation.blocked / (reputation.blocked + reputation.seen) * 0.8);
            result.reasons.push('previously_blocked');
        }

        this.ipReputation.set(ip, { data: result, timestamp: Date.now() });

        return result;
    }

    isPrivateIP(ip) {
        const privateRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./,
            /^127\./,
            /^169\.254\./,
            /^::1$/,
            /^fc00:/,
            /^fe80:/
        ];

        return privateRanges.some(range => range.test(ip));
    }

    isDatacenterIP(ip) {
        const datacenterRanges = [
            /^35\.(1[89]|2[0-9]|3[0-9])\./,
            /^34\./,
            /^104\.196\./,
            /^52\./,
            /^54\./,
            /^13\.([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-7])\./,
            /^18\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-3][0-9]|24[0-3])\./,
            /^20\./
        ];

        return datacenterRanges.some(range => range.test(ip));
    }

    isTorExitNode(ip) {
        return false;
    }

    isVPN(ip) {
        return false;
    }

    getIPReputation(ip) {
        const rep = this.ipReputation.get(`rep:${ip}`);
        return rep || { seen: 0, blocked: 0 };
    }

    recordIPActivity(ip, blocked = false) {
        const key = `rep:${ip}`;
        const rep = this.ipReputation.get(key) || { seen: 0, blocked: 0 };
        rep.seen++;
        if (blocked) rep.blocked++;
        this.ipReputation.set(key, rep);
    }

    analyzeUserAgent(userAgent) {
        if (!userAgent) {
            return { risk: 0.6, reason: 'missing_user_agent', isBot: true };
        }

        const ua = userAgent.toLowerCase();
        
        for (const pattern of this.userAgentBlacklist) {
            if (ua.includes(pattern)) {
                return { risk: 0.8, reason: 'blacklisted_user_agent', pattern, isBot: true };
            }
        }

        if (ua.length < 20) {
            return { risk: 0.5, reason: 'suspicious_short_ua', isBot: true };
        }

        if (!/mozilla|chrome|safari|firefox|edge|opera/i.test(ua)) {
            return { risk: 0.4, reason: 'non_browser_ua', isBot: true };
        }

        const version = ua.match(/chrome\/(\d+)/i);
        if (version && parseInt(version[1]) < 70) {
            return { risk: 0.3, reason: 'outdated_browser', isBot: false };
        }

        return { risk: 0, reason: 'legitimate', isBot: false };
    }

    analyzePayload(request) {
        const result = {
            risk: 0,
            threats: [],
            sanitized: false
        };

        const payloadStr = this.extractPayloadString(request);
        if (!payloadStr) return result;

        for (const pattern of this.suspiciousPatterns) {
            if (pattern.test(payloadStr)) {
                result.threats.push({
                    type: this.classifyThreat(pattern),
                    pattern: pattern.toString()
                });
                result.risk = Math.max(result.risk, 0.9);
            }
        }

        if (payloadStr.length > 100000) {
            result.threats.push({ type: 'large_payload' });
            result.risk = Math.max(result.risk, 0.3);
        }

        const nullBytes = (payloadStr.match(/\x00/g) || []).length;
        if (nullBytes > 0) {
            result.threats.push({ type: 'null_bytes', count: nullBytes });
            result.risk = Math.max(result.risk, 0.7);
        }

        return result;
    }

    extractPayloadString(request) {
        const parts = [];
        
        if (request.body) {
            parts.push(typeof request.body === 'string' ? request.body : JSON.stringify(request.body));
        }
        if (request.query) {
            parts.push(typeof request.query === 'string' ? request.query : JSON.stringify(request.query));
        }
        if (request.path) {
            parts.push(request.path);
        }

        return parts.join(' ');
    }

    classifyThreat(pattern) {
        const patternStr = pattern.toString().toLowerCase();
        
        if (patternStr.includes('select') || patternStr.includes('union')) return 'sql_injection';
        if (patternStr.includes('script') || patternStr.includes('javascript')) return 'xss';
        if (patternStr.includes('..') || patternStr.includes('etc/passwd')) return 'path_traversal';
        if (patternStr.includes('cmd') || patternStr.includes('powershell')) return 'command_injection';
        if (patternStr.includes('eval') || patternStr.includes('base64')) return 'code_injection';
        if (patternStr.includes('${') || patternStr.includes('{{')) return 'template_injection';
        
        return 'unknown';
    }

    analyzeGeo(geo) {
        if (!geo || !geo.country) {
            return { risk: 0.1, reason: 'unknown_geo' };
        }

        const countryRisk = this.geoRisk.get(geo.country.toUpperCase()) || 0;
        
        return {
            risk: countryRisk,
            country: geo.country,
            reason: countryRisk > 0.5 ? 'high_risk_country' : 'normal'
        };
    }

    analyzeASN(asn) {
        if (!asn) {
            return { risk: 0, reason: 'unknown_asn' };
        }

        const asnUpper = asn.toUpperCase();
        
        for (const [provider, risk] of this.asnRisk.entries()) {
            if (asnUpper.includes(provider)) {
                return {
                    risk,
                    asn,
                    reason: 'cloud_provider',
                    provider
                };
            }
        }

        return { risk: 0, asn, reason: 'normal' };
    }

    analyzeReferrer(referrer) {
        if (!referrer) {
            return { risk: 0.1, reason: 'direct_access' };
        }

        try {
            const url = new URL(referrer);
            
            const suspiciousDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'];
            if (suspiciousDomains.some(d => url.hostname.includes(d))) {
                return { risk: 0.3, reason: 'url_shortener', domain: url.hostname };
            }

            return { risk: 0, reason: 'normal', domain: url.hostname };
        } catch {
            return { risk: 0.2, reason: 'invalid_referrer' };
        }
    }

    analyzeHeaders(headers) {
        if (!headers) {
            return { risk: 0.3, reason: 'no_headers' };
        }

        const result = {
            risk: 0,
            anomalies: []
        };

        const requiredHeaders = ['host', 'accept', 'accept-language'];
        const missingRequired = requiredHeaders.filter(h => !headers[h]);
        
        if (missingRequired.length > 0) {
            result.anomalies.push({ type: 'missing_headers', headers: missingRequired });
            result.risk = Math.max(result.risk, missingRequired.length * 0.1);
        }

        if (headers['x-forwarded-for']) {
            const ips = headers['x-forwarded-for'].split(',');
            if (ips.length > 5) {
                result.anomalies.push({ type: 'excessive_proxies', count: ips.length });
                result.risk = Math.max(result.risk, 0.4);
            }
        }

        const suspiciousHeaders = ['x-attack', 'x-scanner', 'x-hack'];
        for (const header of suspiciousHeaders) {
            if (headers[header]) {
                result.anomalies.push({ type: 'suspicious_header', header });
                result.risk = Math.max(result.risk, 0.8);
            }
        }

        return result;
    }

    calculateOverallRisk(results) {
        const weights = {
            ip: 0.25,
            userAgent: 0.15,
            payload: 0.3,
            geo: 0.1,
            asn: 0.1,
            referrer: 0.05,
            headers: 0.05
        };

        let totalRisk = 0;
        let totalWeight = 0;

        for (const [key, weight] of Object.entries(weights)) {
            if (results[key] && typeof results[key].risk === 'number') {
                totalRisk += results[key].risk * weight;
                totalWeight += weight;
            }
        }

        return totalWeight > 0 ? totalRisk / totalWeight : 0;
    }

    identifyThreats(results) {
        const threats = [];

        if (results.ip?.type === 'tor') {
            threats.push({ type: 'anonymizer', severity: 'high', source: 'ip' });
        }
        if (results.userAgent?.isBot) {
            threats.push({ type: 'bot', severity: 'medium', source: 'user_agent' });
        }
        if (results.payload?.threats?.length > 0) {
            for (const threat of results.payload.threats) {
                threats.push({ type: threat.type, severity: 'critical', source: 'payload' });
            }
        }
        if (results.geo?.risk > 0.5) {
            threats.push({ type: 'high_risk_geo', severity: 'medium', source: 'geo' });
        }

        return threats;
    }

    getRecommendation(riskScore, results) {
        if (results.payload?.threats?.some(t => ['sql_injection', 'xss', 'command_injection'].includes(t.type))) {
            return { action: 'block', reason: 'attack_detected' };
        }

        if (riskScore >= 0.8) {
            return { action: 'block', reason: 'high_risk' };
        }
        if (riskScore >= 0.6) {
            return { action: 'challenge', reason: 'elevated_risk' };
        }
        if (riskScore >= 0.4) {
            return { action: 'monitor', reason: 'suspicious' };
        }

        return { action: 'allow', reason: 'low_risk' };
    }

    addThreatFeed(name, data) {
        this.threatFeeds.set(name, {
            data,
            addedAt: Date.now()
        });
    }

    getThreatFeed(name) {
        return this.threatFeeds.get(name);
    }

    clearCache() {
        const now = Date.now();
        
        for (const [key, value] of this.ipReputation.entries()) {
            if (value.timestamp && now - value.timestamp > this.cacheTimeout) {
                this.ipReputation.delete(key);
            }
        }
    }
}

export default ThreatIntelligence;
