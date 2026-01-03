import EntropyCalculator from '../utils/EntropyCalculator.js';
import MathUtils from '../utils/MathUtils.js';

class Fingerprinter {
    constructor(options = {}) {
        this.hashSeed = options.hashSeed || 0x811c9dc5;
        this.fingerprintCache = new Map();
        this.knownFingerprints = new Map();
        this.suspiciousSignatures = new Set();
        this.weights = {
            userAgent: 0.15,
            acceptLanguage: 0.1,
            acceptEncoding: 0.05,
            connection: 0.05,
            ip: 0.2,
            timezone: 0.1,
            screenResolution: 0.1,
            colorDepth: 0.05,
            platform: 0.05,
            plugins: 0.05,
            canvas: 0.05,
            webgl: 0.05
        };
    }

    generate(request) {
        const components = this.extractComponents(request);
        const fingerprint = this.computeFingerprint(components);
        const stability = this.calculateStability(request.userId, fingerprint);
        const anomalyScore = this.detectAnomalies(components);
        
        return {
            fingerprint,
            components,
            stability,
            anomalyScore,
            confidence: this.calculateConfidence(components),
            isBot: this.detectBot(components),
            isSuspicious: this.checkSuspicious(fingerprint, components)
        };
    }

    extractComponents(request) {
        const headers = request.headers || {};
        const client = request.client || {};

        return {
            userAgent: this.parseUserAgent(headers['user-agent'] || ''),
            acceptLanguage: this.normalizeAcceptLanguage(headers['accept-language'] || ''),
            acceptEncoding: headers['accept-encoding'] || '',
            connection: headers['connection'] || '',
            ip: this.hashIP(request.ip || ''),
            ipClass: this.classifyIP(request.ip || ''),
            timezone: client.timezone || null,
            timezoneOffset: client.timezoneOffset || null,
            screenResolution: client.screenResolution || null,
            colorDepth: client.colorDepth || null,
            platform: client.platform || headers['sec-ch-ua-platform'] || null,
            mobile: client.mobile || headers['sec-ch-ua-mobile'] === '?1',
            plugins: this.hashPlugins(client.plugins || []),
            canvas: client.canvasHash || null,
            webgl: client.webglHash || null,
            fonts: this.hashFonts(client.fonts || []),
            audio: client.audioHash || null,
            doNotTrack: headers['dnt'] || client.doNotTrack,
            cookiesEnabled: client.cookiesEnabled,
            localStorage: client.localStorage,
            sessionStorage: client.sessionStorage,
            cpuCores: client.hardwareConcurrency,
            deviceMemory: client.deviceMemory,
            touchSupport: client.touchSupport,
            connectionType: client.connectionType,
            downlink: client.downlink
        };
    }

    parseUserAgent(ua) {
        if (!ua) return { raw: '', parsed: null };

        const parsed = {
            browser: null,
            browserVersion: null,
            os: null,
            osVersion: null,
            device: null,
            isBot: false
        };

        const botPatterns = [
            /bot/i, /crawler/i, /spider/i, /scraper/i,
            /headless/i, /phantom/i, /selenium/i, /puppeteer/i,
            /playwright/i, /webdriver/i
        ];

        for (const pattern of botPatterns) {
            if (pattern.test(ua)) {
                parsed.isBot = true;
                break;
            }
        }

        const browserPatterns = [
            { name: 'Chrome', pattern: /Chrome\/(\d+)/ },
            { name: 'Firefox', pattern: /Firefox\/(\d+)/ },
            { name: 'Safari', pattern: /Version\/(\d+).*Safari/ },
            { name: 'Edge', pattern: /Edg\/(\d+)/ },
            { name: 'Opera', pattern: /OPR\/(\d+)/ }
        ];

        for (const { name, pattern } of browserPatterns) {
            const match = ua.match(pattern);
            if (match) {
                parsed.browser = name;
                parsed.browserVersion = parseInt(match[1]);
                break;
            }
        }

        const osPatterns = [
            { name: 'Windows', pattern: /Windows NT (\d+\.\d+)/ },
            { name: 'macOS', pattern: /Mac OS X (\d+[._]\d+)/ },
            { name: 'Linux', pattern: /Linux/ },
            { name: 'Android', pattern: /Android (\d+)/ },
            { name: 'iOS', pattern: /iPhone OS (\d+)/ }
        ];

        for (const { name, pattern } of osPatterns) {
            const match = ua.match(pattern);
            if (match) {
                parsed.os = name;
                parsed.osVersion = match[1] ? match[1].replace('_', '.') : null;
                break;
            }
        }

        if (/Mobile|Android|iPhone|iPad/.test(ua)) {
            parsed.device = 'mobile';
        } else if (/Tablet|iPad/.test(ua)) {
            parsed.device = 'tablet';
        } else {
            parsed.device = 'desktop';
        }

        return { raw: ua, parsed, hash: this.fnv1a(ua) };
    }

    normalizeAcceptLanguage(al) {
        if (!al) return [];
        
        const languages = al.split(',').map(lang => {
            const [code, quality] = lang.trim().split(';q=');
            return {
                code: code.toLowerCase().split('-')[0],
                quality: quality ? parseFloat(quality) : 1
            };
        });

        return languages.sort((a, b) => b.quality - a.quality).map(l => l.code);
    }

    hashIP(ip) {
        if (!ip) return null;
        const parts = ip.split('.').slice(0, 3);
        return this.fnv1a(parts.join('.'));
    }

    classifyIP(ip) {
        if (!ip) return 'unknown';

        const privateRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./,
            /^127\./
        ];

        for (const range of privateRanges) {
            if (range.test(ip)) return 'private';
        }

        const datacenterRanges = [
            /^35\./, /^34\./, /^104\./, /^13\./,
            /^52\./, /^54\./
        ];

        for (const range of datacenterRanges) {
            if (range.test(ip)) return 'datacenter';
        }

        return 'residential';
    }

    hashPlugins(plugins) {
        if (!plugins || plugins.length === 0) return null;
        return this.fnv1a(plugins.sort().join('|'));
    }

    hashFonts(fonts) {
        if (!fonts || fonts.length === 0) return null;
        return this.fnv1a(fonts.sort().join('|'));
    }

    fnv1a(str) {
        let hash = this.hashSeed;
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
        }
        return (hash >>> 0).toString(16);
    }

    computeFingerprint(components) {
        const significantComponents = [
            components.userAgent?.hash,
            components.ip,
            components.acceptLanguage?.join(','),
            components.timezone,
            components.screenResolution,
            components.platform,
            components.canvas,
            components.webgl,
            components.plugins,
            components.fonts
        ].filter(Boolean);

        return this.fnv1a(significantComponents.join('|'));
    }

    calculateStability(userId, fingerprint) {
        if (!userId) return { stable: true, changes: 0, history: [] };

        const key = `fp:${userId}`;
        let history = this.fingerprintCache.get(key) || [];
        
        const changes = history.filter(h => h.fingerprint !== fingerprint).length;
        const recentChanges = history.slice(-10).filter(h => h.fingerprint !== fingerprint).length;

        history.push({ fingerprint, timestamp: Date.now() });
        
        if (history.length > 100) {
            history = history.slice(-100);
        }
        
        this.fingerprintCache.set(key, history);

        const uniqueFingerprints = new Set(history.map(h => h.fingerprint)).size;
        
        return {
            stable: recentChanges < 3,
            changes,
            recentChanges,
            uniqueFingerprints,
            history: history.slice(-5).map(h => ({
                fingerprint: h.fingerprint.substring(0, 8),
                timestamp: h.timestamp
            }))
        };
    }

    detectAnomalies(components) {
        let anomalyScore = 0;
        const anomalies = [];

        if (components.userAgent?.parsed?.isBot) {
            anomalyScore += 0.8;
            anomalies.push('bot_user_agent');
        }

        if (!components.userAgent?.raw) {
            anomalyScore += 0.3;
            anomalies.push('missing_user_agent');
        }

        if (components.ipClass === 'datacenter') {
            anomalyScore += 0.4;
            anomalies.push('datacenter_ip');
        }

        const uaParsed = components.userAgent?.parsed;
        if (uaParsed) {
            if (uaParsed.browser === 'Chrome' && uaParsed.browserVersion < 70) {
                anomalyScore += 0.2;
                anomalies.push('outdated_browser');
            }
        }

        if (components.timezone === null && components.screenResolution === null) {
            anomalyScore += 0.3;
            anomalies.push('missing_client_data');
        }

        if (components.canvas === null && components.webgl === null) {
            anomalyScore += 0.2;
            anomalies.push('no_canvas_webgl');
        }

        if (components.screenResolution) {
            const [width] = components.screenResolution.split('x').map(Number);
            if (width > 3840 || width < 320) {
                anomalyScore += 0.15;
                anomalies.push('unusual_resolution');
            }
        }

        if (uaParsed?.device === 'mobile' && !components.touchSupport) {
            anomalyScore += 0.25;
            anomalies.push('mobile_no_touch');
        }

        if (components.plugins && components.plugins.length === 0 && 
            uaParsed?.browser === 'Chrome' && uaParsed?.os === 'Windows') {
            anomalyScore += 0.15;
            anomalies.push('no_plugins_chrome');
        }

        if (components.cookiesEnabled === false) {
            anomalyScore += 0.1;
            anomalies.push('cookies_disabled');
        }

        return {
            score: MathUtils.clamp(anomalyScore, 0, 1),
            anomalies
        };
    }

    calculateConfidence(components) {
        let totalWeight = 0;
        let presentWeight = 0;

        for (const [key, weight] of Object.entries(this.weights)) {
            totalWeight += weight;
            if (components[key] !== null && components[key] !== undefined) {
                presentWeight += weight;
            }
        }

        const baseConfidence = presentWeight / totalWeight;

        let qualityBonus = 0;
        if (components.canvas) qualityBonus += 0.05;
        if (components.webgl) qualityBonus += 0.05;
        if (components.fonts) qualityBonus += 0.03;
        if (components.audio) qualityBonus += 0.02;

        return MathUtils.clamp(baseConfidence + qualityBonus, 0, 1);
    }

    detectBot(components) {
        const signals = {
            userAgentBot: components.userAgent?.parsed?.isBot || false,
            noJavaScript: components.screenResolution === null && 
                          components.timezone === null,
            phantomNavigator: components.plugins?.length === 0 && 
                              components.userAgent?.parsed?.browser === 'Chrome',
            headlessChrome: /HeadlessChrome/.test(components.userAgent?.raw || ''),
            webDriver: components.webdriver === true,
            seleniumMarkers: false,
            datacenterIP: components.ipClass === 'datacenter'
        };

        let botScore = 0;
        const weights = {
            userAgentBot: 0.9,
            noJavaScript: 0.7,
            phantomNavigator: 0.6,
            headlessChrome: 0.95,
            webDriver: 1.0,
            seleniumMarkers: 0.9,
            datacenterIP: 0.3
        };

        for (const [signal, detected] of Object.entries(signals)) {
            if (detected) {
                botScore += weights[signal] || 0.5;
            }
        }

        return {
            isBot: botScore > 0.7,
            score: MathUtils.clamp(botScore, 0, 1),
            signals
        };
    }

    checkSuspicious(fingerprint, components) {
        if (this.suspiciousSignatures.has(fingerprint)) {
            return { suspicious: true, reason: 'known_bad_fingerprint' };
        }

        const known = this.knownFingerprints.get(fingerprint);
        if (known && known.blocked > 3) {
            return { suspicious: true, reason: 'previously_blocked' };
        }

        const anomalyResult = this.detectAnomalies(components);
        if (anomalyResult.score > 0.7) {
            return { suspicious: true, reason: 'high_anomaly_score', anomalies: anomalyResult.anomalies };
        }

        return { suspicious: false };
    }

    compare(fp1, fp2) {
        const components1 = typeof fp1 === 'object' ? fp1 : { fingerprint: fp1 };
        const components2 = typeof fp2 === 'object' ? fp2 : { fingerprint: fp2 };

        if (components1.fingerprint === components2.fingerprint) {
            return { similarity: 1, match: true };
        }

        let matchScore = 0;
        let totalWeight = 0;

        for (const [key, weight] of Object.entries(this.weights)) {
            if (components1[key] !== undefined && components2[key] !== undefined) {
                totalWeight += weight;
                if (components1[key] === components2[key]) {
                    matchScore += weight;
                } else if (typeof components1[key] === 'string' && typeof components2[key] === 'string') {
                    const similarity = this.stringSimilarity(components1[key], components2[key]);
                    matchScore += weight * similarity;
                }
            }
        }

        const similarity = totalWeight > 0 ? matchScore / totalWeight : 0;

        return {
            similarity,
            match: similarity > 0.8
        };
    }

    stringSimilarity(str1, str2) {
        if (str1 === str2) return 1;
        if (!str1 || !str2) return 0;

        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;

        if (longer.length === 0) return 1;

        const editDistance = this.levenshteinDistance(longer, shorter);
        return (longer.length - editDistance) / longer.length;
    }

    levenshteinDistance(str1, str2) {
        const m = str1.length;
        const n = str2.length;
        const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

        for (let i = 0; i <= m; i++) dp[i][0] = i;
        for (let j = 0; j <= n; j++) dp[0][j] = j;

        for (let i = 1; i <= m; i++) {
            for (let j = 1; j <= n; j++) {
                if (str1[i - 1] === str2[j - 1]) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = Math.min(
                        dp[i - 1][j] + 1,
                        dp[i][j - 1] + 1,
                        dp[i - 1][j - 1] + 1
                    );
                }
            }
        }

        return dp[m][n];
    }

    markSuspicious(fingerprint) {
        this.suspiciousSignatures.add(fingerprint);
    }

    recordBlocked(fingerprint) {
        const record = this.knownFingerprints.get(fingerprint) || { seen: 0, blocked: 0 };
        record.blocked++;
        record.lastBlocked = Date.now();
        this.knownFingerprints.set(fingerprint, record);
    }

    recordSeen(fingerprint) {
        const record = this.knownFingerprints.get(fingerprint) || { seen: 0, blocked: 0 };
        record.seen++;
        record.lastSeen = Date.now();
        this.knownFingerprints.set(fingerprint, record);
    }

    getStats() {
        return {
            cachedFingerprints: this.fingerprintCache.size,
            knownFingerprints: this.knownFingerprints.size,
            suspiciousSignatures: this.suspiciousSignatures.size
        };
    }

    cleanup(maxAge = 86400000) {
        const now = Date.now();
        
        for (const [key, history] of this.fingerprintCache.entries()) {
            const recent = history.filter(h => now - h.timestamp < maxAge);
            if (recent.length === 0) {
                this.fingerprintCache.delete(key);
            } else {
                this.fingerprintCache.set(key, recent);
            }
        }

        for (const [fp, record] of this.knownFingerprints.entries()) {
            const lastActivity = Math.max(record.lastSeen || 0, record.lastBlocked || 0);
            if (now - lastActivity > maxAge * 7) {
                this.knownFingerprints.delete(fp);
            }
        }
    }
}

export default Fingerprinter;
