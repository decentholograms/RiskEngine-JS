import MathUtils from '../utils/MathUtils.js';
import EntropyCalculator from '../utils/EntropyCalculator.js';
import TimeSeriesAnalyzer from '../utils/TimeSeriesAnalyzer.js';

class BehaviorAnalyzer {
    constructor(options = {}) {
        this.timeWindow = options.timeWindow || 3600000;
        this.minSamples = options.minSamples || 10;
        this.anomalyThreshold = options.anomalyThreshold || 2.5;
        this.timeSeriesAnalyzer = new TimeSeriesAnalyzer();
        this.behaviorProfiles = new Map();
    }

    analyze(userId, events) {
        if (!events || events.length < this.minSamples) {
            return { reliable: false, riskScore: 0.5, factors: [] };
        }

        const profile = this.getOrCreateProfile(userId);
        const features = this.extractFeatures(events);
        const anomalies = this.detectAnomalies(features, profile);
        const velocityScore = this.analyzeVelocity(events);
        const rhythmScore = this.analyzeRhythm(events);
        const diversityScore = this.analyzeDiversity(events);
        const automationScore = this.detectAutomation(events);
        const sessionScore = this.analyzeSessionPatterns(events);
        
        this.updateProfile(userId, features);

        const factors = [];
        
        if (anomalies.score > 0.3) {
            factors.push({ type: 'anomaly', score: anomalies.score, details: anomalies.details });
        }
        if (velocityScore > 0.5) {
            factors.push({ type: 'velocity', score: velocityScore });
        }
        if (rhythmScore > 0.4) {
            factors.push({ type: 'rhythm', score: rhythmScore });
        }
        if (diversityScore < 0.2) {
            factors.push({ type: 'lowDiversity', score: 1 - diversityScore });
        }
        if (automationScore > 0.6) {
            factors.push({ type: 'automation', score: automationScore });
        }
        if (sessionScore > 0.5) {
            factors.push({ type: 'sessionAnomaly', score: sessionScore });
        }

        const weights = {
            anomaly: 0.25,
            velocity: 0.2,
            rhythm: 0.15,
            lowDiversity: 0.1,
            automation: 0.2,
            sessionAnomaly: 0.1
        };

        let weightedSum = 0;
        let totalWeight = 0;

        for (const factor of factors) {
            const weight = weights[factor.type] || 0.1;
            weightedSum += factor.score * weight;
            totalWeight += weight;
        }

        const riskScore = totalWeight > 0 ? weightedSum / totalWeight : 0;

        return {
            reliable: true,
            riskScore: MathUtils.clamp(riskScore, 0, 1),
            factors,
            metrics: {
                anomalyScore: anomalies.score,
                velocityScore,
                rhythmScore,
                diversityScore,
                automationScore,
                sessionScore
            }
        };
    }

    extractFeatures(events) {
        const timestamps = events.map(e => e.timestamp);
        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        const actions = events.map(e => e.action);
        const endpoints = events.map(e => e.endpoint);
        const responseTimes = events.filter(e => e.responseTime).map(e => e.responseTime);
        const payloadSizes = events.filter(e => e.payloadSize).map(e => e.payloadSize);

        return {
            intervalMean: MathUtils.mean(intervals),
            intervalStd: MathUtils.standardDeviation(intervals),
            intervalEntropy: EntropyCalculator.timeSeriesEntropy(timestamps),
            actionEntropy: EntropyCalculator.normalizedEntropy(actions),
            endpointEntropy: EntropyCalculator.normalizedEntropy(endpoints),
            eventCount: events.length,
            uniqueActions: new Set(actions).size,
            uniqueEndpoints: new Set(endpoints).size,
            avgResponseTime: MathUtils.mean(responseTimes),
            responseTimeStd: MathUtils.standardDeviation(responseTimes),
            avgPayloadSize: MathUtils.mean(payloadSizes),
            timeSpan: timestamps.length > 1 ? timestamps[timestamps.length - 1] - timestamps[0] : 0,
            eventsPerMinute: events.length / Math.max(1, (timestamps[timestamps.length - 1] - timestamps[0]) / 60000)
        };
    }

    getOrCreateProfile(userId) {
        if (!this.behaviorProfiles.has(userId)) {
            this.behaviorProfiles.set(userId, {
                featureHistory: [],
                baselineFeatures: null,
                lastUpdated: Date.now(),
                confidence: 0
            });
        }
        return this.behaviorProfiles.get(userId);
    }

    updateProfile(userId, features) {
        const profile = this.getOrCreateProfile(userId);
        profile.featureHistory.push({ ...features, timestamp: Date.now() });
        
        if (profile.featureHistory.length > 100) {
            profile.featureHistory = profile.featureHistory.slice(-100);
        }

        if (profile.featureHistory.length >= 5) {
            profile.baselineFeatures = this.calculateBaseline(profile.featureHistory);
            profile.confidence = Math.min(profile.featureHistory.length / 20, 1);
        }

        profile.lastUpdated = Date.now();
    }

    calculateBaseline(featureHistory) {
        const baseline = {};
        const keys = Object.keys(featureHistory[0]).filter(k => k !== 'timestamp');
        
        for (const key of keys) {
            const values = featureHistory.map(f => f[key]).filter(v => typeof v === 'number');
            if (values.length > 0) {
                baseline[key] = {
                    mean: MathUtils.mean(values),
                    std: MathUtils.standardDeviation(values),
                    median: MathUtils.median(values),
                    q1: MathUtils.percentile(values, 25),
                    q3: MathUtils.percentile(values, 75)
                };
            }
        }
        
        return baseline;
    }

    detectAnomalies(features, profile) {
        if (!profile.baselineFeatures || profile.confidence < 0.3) {
            return { score: 0, details: [] };
        }

        const details = [];
        let totalDeviation = 0;
        let count = 0;

        for (const [key, baseline] of Object.entries(profile.baselineFeatures)) {
            if (features[key] !== undefined && baseline.std > 0) {
                const zScore = Math.abs(MathUtils.zScore(features[key], baseline.mean, baseline.std));
                
                if (zScore > this.anomalyThreshold) {
                    details.push({
                        feature: key,
                        value: features[key],
                        expected: baseline.mean,
                        zScore
                    });
                }
                
                totalDeviation += Math.min(zScore / this.anomalyThreshold, 2);
                count++;
            }
        }

        const score = count > 0 ? MathUtils.sigmoid(totalDeviation / count - 1) : 0;
        
        return { score, details };
    }

    analyzeVelocity(events) {
        const timestamps = events.map(e => e.timestamp);
        if (timestamps.length < 2) return 0;

        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        const minInterval = Math.min(...intervals);
        const avgInterval = MathUtils.mean(intervals);
        const eventsPerSecond = 1000 / avgInterval;

        let score = 0;

        if (minInterval < 50) {
            score += 0.4;
        } else if (minInterval < 100) {
            score += 0.2;
        }

        if (eventsPerSecond > 10) {
            score += 0.3;
        } else if (eventsPerSecond > 5) {
            score += 0.15;
        }

        const burstScore = this.detectBursts(intervals);
        score += burstScore * 0.3;

        return MathUtils.clamp(score, 0, 1);
    }

    detectBursts(intervals) {
        if (intervals.length < 5) return 0;

        const mean = MathUtils.mean(intervals);
        const threshold = mean * 0.3;
        
        let burstCount = 0;
        let inBurst = false;
        let burstLength = 0;
        let maxBurstLength = 0;

        for (const interval of intervals) {
            if (interval < threshold) {
                if (!inBurst) {
                    burstCount++;
                    inBurst = true;
                    burstLength = 1;
                } else {
                    burstLength++;
                }
            } else {
                if (inBurst) {
                    maxBurstLength = Math.max(maxBurstLength, burstLength);
                    inBurst = false;
                }
            }
        }

        if (inBurst) {
            maxBurstLength = Math.max(maxBurstLength, burstLength);
        }

        const burstRatio = burstCount / Math.max(1, intervals.length / 10);
        const lengthScore = Math.min(maxBurstLength / 10, 1);
        
        return (burstRatio + lengthScore) / 2;
    }

    analyzeRhythm(events) {
        const timestamps = events.map(e => e.timestamp);
        if (timestamps.length < 10) return 0;

        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        const std = MathUtils.standardDeviation(intervals);
        const mean = MathUtils.mean(intervals);
        const cv = mean > 0 ? std / mean : 0;

        let rhythmScore = 0;

        if (cv < 0.1) {
            rhythmScore = 0.8;
        } else if (cv < 0.2) {
            rhythmScore = 0.5;
        } else if (cv < 0.3) {
            rhythmScore = 0.2;
        }

        const roundedIntervals = intervals.filter(i => {
            const rounded = Math.round(i / 100) * 100;
            return Math.abs(i - rounded) < 20;
        });
        
        const roundedRatio = roundedIntervals.length / intervals.length;
        if (roundedRatio > 0.8) {
            rhythmScore += 0.2;
        }

        return MathUtils.clamp(rhythmScore, 0, 1);
    }

    analyzeDiversity(events) {
        const actions = events.map(e => e.action);
        const endpoints = events.map(e => e.endpoint);
        const userAgents = events.map(e => e.userAgent).filter(Boolean);

        const actionDiversity = new Set(actions).size / Math.max(actions.length, 1);
        const endpointDiversity = new Set(endpoints).size / Math.max(endpoints.length, 1);
        const uaDiversity = new Set(userAgents).size / Math.max(userAgents.length, 1);

        const actionEntropy = EntropyCalculator.normalizedEntropy(actions);
        const endpointEntropy = EntropyCalculator.normalizedEntropy(endpoints);

        return (actionDiversity * 0.2 + endpointDiversity * 0.2 + 
                actionEntropy * 0.3 + endpointEntropy * 0.3);
    }

    detectAutomation(events) {
        const timestamps = events.map(e => e.timestamp);
        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        let automationScore = 0;

        const perfectIntervals = intervals.filter(i => i % 1000 === 0 || i % 500 === 0 || i % 100 === 0);
        automationScore += (perfectIntervals.length / Math.max(intervals.length, 1)) * 0.3;

        const uniqueIntervals = new Set(intervals.map(i => Math.round(i / 10))).size;
        const intervalRepetition = 1 - (uniqueIntervals / Math.max(intervals.length, 1));
        automationScore += intervalRepetition * 0.2;

        const sequenceScore = this.detectSequentialPatterns(events);
        automationScore += sequenceScore * 0.25;

        const missingHumanMarkers = this.checkHumanMarkers(events);
        automationScore += missingHumanMarkers * 0.25;

        return MathUtils.clamp(automationScore, 0, 1);
    }

    detectSequentialPatterns(events) {
        if (events.length < 6) return 0;

        const actions = events.map(e => e.action);
        const patterns = new Map();
        
        for (let len = 2; len <= 5; len++) {
            for (let i = 0; i <= actions.length - len; i++) {
                const pattern = actions.slice(i, i + len).join(',');
                patterns.set(pattern, (patterns.get(pattern) || 0) + 1);
            }
        }

        let maxRepetition = 0;
        for (const count of patterns.values()) {
            if (count > maxRepetition) {
                maxRepetition = count;
            }
        }

        const expectedMax = Math.log2(events.length) + 1;
        return Math.min(maxRepetition / expectedMax / 2, 1);
    }

    checkHumanMarkers(events) {
        let missingMarkers = 0;
        let totalChecks = 0;

        const hasMouse = events.some(e => e.mouseMovement);
        if (!hasMouse) {
            missingMarkers++;
        }
        totalChecks++;

        const hasVariableResponseTime = events.filter(e => e.responseTime).length > 0;
        if (hasVariableResponseTime) {
            const responseTimes = events.map(e => e.responseTime).filter(Boolean);
            const cv = MathUtils.standardDeviation(responseTimes) / Math.max(MathUtils.mean(responseTimes), 1);
            if (cv < 0.1) {
                missingMarkers++;
            }
        }
        totalChecks++;

        const hasScrolling = events.some(e => e.scrollPosition !== undefined);
        if (!hasScrolling) {
            missingMarkers += 0.5;
        }
        totalChecks++;

        return missingMarkers / totalChecks;
    }

    analyzeSessionPatterns(events) {
        if (events.length < 5) return 0;

        const timestamps = events.map(e => e.timestamp);
        const sessionStart = timestamps[0];
        const sessionDuration = timestamps[timestamps.length - 1] - sessionStart;

        let score = 0;

        if (sessionDuration < 5000 && events.length > 20) {
            score += 0.4;
        }

        const hours = events.map(e => new Date(e.timestamp).getHours());
        const hourEntropy = EntropyCalculator.normalizedEntropy(hours);
        if (hourEntropy < 0.2) {
            score += 0.2;
        }

        const gaps = [];
        for (let i = 1; i < timestamps.length; i++) {
            const gap = timestamps[i] - timestamps[i - 1];
            if (gap > 60000) {
                gaps.push(gap);
            }
        }

        if (gaps.length === 0 && sessionDuration > 1800000) {
            score += 0.4;
        }

        return MathUtils.clamp(score, 0, 1);
    }

    getProfile(userId) {
        return this.behaviorProfiles.get(userId);
    }

    clearProfile(userId) {
        this.behaviorProfiles.delete(userId);
    }

    clearAllProfiles() {
        this.behaviorProfiles.clear();
    }
}

export default BehaviorAnalyzer;
