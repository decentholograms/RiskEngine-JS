import MathUtils from '../utils/MathUtils.js';
import EntropyCalculator from '../utils/EntropyCalculator.js';

class PatternDetector {
    constructor(options = {}) {
        this.minPatternLength = options.minPatternLength || 2;
        this.maxPatternLength = options.maxPatternLength || 10;
        this.significanceThreshold = options.significanceThreshold || 3;
        this.suspiciousPatterns = new Map();
        this.knownAttackPatterns = this.initializeAttackPatterns();
    }

    initializeAttackPatterns() {
        return {
            bruteForce: {
                pattern: /^(login|auth|signin)+$/i,
                minRepetitions: 5,
                maxInterval: 5000,
                riskMultiplier: 1.5
            },
            enumeration: {
                pattern: /^(user|account|profile|api\/users)+$/i,
                minRepetitions: 10,
                sequentialIds: true,
                riskMultiplier: 1.3
            },
            scraping: {
                pattern: /^(list|search|catalog|products|items)+$/i,
                minRepetitions: 20,
                lowVariance: true,
                riskMultiplier: 1.2
            },
            cardTesting: {
                pattern: /^(payment|checkout|card|validate)+$/i,
                minRepetitions: 3,
                smallAmounts: true,
                riskMultiplier: 2.0
            },
            accountTakeover: {
                pattern: /^(password|reset|recover|2fa|mfa)+$/i,
                minRepetitions: 3,
                riskMultiplier: 1.8
            },
            apiAbuse: {
                pattern: /^(api\/)+/i,
                minRepetitions: 100,
                timeWindow: 60000,
                riskMultiplier: 1.4
            }
        };
    }

    detect(events) {
        if (!events || events.length < this.minPatternLength) {
            return { patterns: [], riskScore: 0, attackType: null };
        }

        const sequencePatterns = this.detectSequencePatterns(events);
        const temporalPatterns = this.detectTemporalPatterns(events);
        const attackPatterns = this.detectKnownAttacks(events);
        const anomalousPatterns = this.detectAnomalousPatterns(events);
        const coordinationPatterns = this.detectCoordinatedBehavior(events);

        const allPatterns = [
            ...sequencePatterns,
            ...temporalPatterns,
            ...attackPatterns,
            ...anomalousPatterns,
            ...coordinationPatterns
        ];

        const riskScore = this.calculatePatternRisk(allPatterns);
        const attackType = this.identifyPrimaryAttack(attackPatterns);

        return {
            patterns: allPatterns,
            riskScore,
            attackType,
            metrics: {
                sequenceCount: sequencePatterns.length,
                temporalCount: temporalPatterns.length,
                attackCount: attackPatterns.length,
                anomalyCount: anomalousPatterns.length
            }
        };
    }

    detectSequencePatterns(events) {
        const patterns = [];
        const actions = events.map(e => e.action || e.endpoint);
        
        for (let len = this.minPatternLength; len <= Math.min(this.maxPatternLength, Math.floor(actions.length / 2)); len++) {
            const found = this.findRepeatingSequences(actions, len);
            
            for (const [sequence, occurrences] of found.entries()) {
                if (occurrences.length >= this.significanceThreshold) {
                    const intervals = this.calculateOccurrenceIntervals(events, occurrences, len);
                    
                    patterns.push({
                        type: 'sequence',
                        sequence: sequence.split(','),
                        length: len,
                        count: occurrences.length,
                        positions: occurrences,
                        intervalStats: {
                            mean: MathUtils.mean(intervals),
                            std: MathUtils.standardDeviation(intervals)
                        },
                        risk: this.calculateSequenceRisk(occurrences.length, len, intervals)
                    });
                }
            }
        }

        return patterns.sort((a, b) => b.risk - a.risk).slice(0, 10);
    }

    findRepeatingSequences(actions, length) {
        const sequences = new Map();
        
        for (let i = 0; i <= actions.length - length; i++) {
            const seq = actions.slice(i, i + length).join(',');
            
            if (!sequences.has(seq)) {
                sequences.set(seq, []);
            }
            sequences.get(seq).push(i);
        }

        for (const [seq, positions] of sequences.entries()) {
            if (positions.length < this.significanceThreshold) {
                sequences.delete(seq);
            }
        }

        return sequences;
    }

    calculateOccurrenceIntervals(events, positions, length) {
        const intervals = [];
        
        for (let i = 1; i < positions.length; i++) {
            const prevEnd = events[positions[i - 1] + length - 1]?.timestamp || 0;
            const currStart = events[positions[i]]?.timestamp || 0;
            intervals.push(currStart - prevEnd);
        }

        return intervals;
    }

    calculateSequenceRisk(count, length, intervals) {
        let risk = 0;
        
        risk += Math.log2(count) / 10;
        
        risk += (length / this.maxPatternLength) * 0.3;
        
        if (intervals.length > 0) {
            const cv = MathUtils.standardDeviation(intervals) / Math.max(MathUtils.mean(intervals), 1);
            if (cv < 0.2) {
                risk += 0.3;
            }
        }

        return MathUtils.clamp(risk, 0, 1);
    }

    detectTemporalPatterns(events) {
        const patterns = [];
        const timestamps = events.map(e => e.timestamp);
        
        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        const periodicPattern = this.detectPeriodicity(intervals);
        if (periodicPattern) {
            patterns.push({
                type: 'periodic',
                period: periodicPattern.period,
                confidence: periodicPattern.confidence,
                risk: periodicPattern.confidence * 0.6
            });
        }

        const bursts = this.detectBurstPatterns(timestamps);
        for (const burst of bursts) {
            patterns.push({
                type: 'burst',
                ...burst,
                risk: this.calculateBurstRisk(burst)
            });
        }

        const clockPattern = this.detectClockAlignment(timestamps);
        if (clockPattern.aligned) {
            patterns.push({
                type: 'clockAligned',
                alignment: clockPattern.alignment,
                count: clockPattern.count,
                risk: clockPattern.count / timestamps.length * 0.5
            });
        }

        return patterns;
    }

    detectPeriodicity(intervals) {
        if (intervals.length < 10) return null;

        const candidates = new Map();
        
        for (let i = 0; i < intervals.length; i++) {
            const rounded = Math.round(intervals[i] / 100) * 100;
            candidates.set(rounded, (candidates.get(rounded) || 0) + 1);
        }

        let bestPeriod = 0;
        let bestCount = 0;
        
        for (const [period, count] of candidates.entries()) {
            if (count > bestCount && period > 0) {
                bestCount = count;
                bestPeriod = period;
            }
        }

        const confidence = bestCount / intervals.length;
        
        if (confidence > 0.3) {
            return { period: bestPeriod, confidence };
        }

        return null;
    }

    detectBurstPatterns(timestamps) {
        const bursts = [];
        const avgInterval = (timestamps[timestamps.length - 1] - timestamps[0]) / timestamps.length;
        const burstThreshold = avgInterval * 0.2;

        let burstStart = 0;
        let burstCount = 1;

        for (let i = 1; i < timestamps.length; i++) {
            const interval = timestamps[i] - timestamps[i - 1];
            
            if (interval < burstThreshold) {
                burstCount++;
            } else {
                if (burstCount >= 5) {
                    bursts.push({
                        startIndex: burstStart,
                        endIndex: i - 1,
                        count: burstCount,
                        duration: timestamps[i - 1] - timestamps[burstStart],
                        rate: burstCount / ((timestamps[i - 1] - timestamps[burstStart]) / 1000)
                    });
                }
                burstStart = i;
                burstCount = 1;
            }
        }

        if (burstCount >= 5) {
            bursts.push({
                startIndex: burstStart,
                endIndex: timestamps.length - 1,
                count: burstCount,
                duration: timestamps[timestamps.length - 1] - timestamps[burstStart],
                rate: burstCount / ((timestamps[timestamps.length - 1] - timestamps[burstStart]) / 1000)
            });
        }

        return bursts;
    }

    calculateBurstRisk(burst) {
        let risk = 0;
        
        if (burst.rate > 10) {
            risk += 0.4;
        } else if (burst.rate > 5) {
            risk += 0.2;
        }

        risk += Math.min(burst.count / 50, 0.4);
        
        return MathUtils.clamp(risk, 0, 1);
    }

    detectClockAlignment(timestamps) {
        let alignedCount = 0;
        const alignments = { second: 0, minute: 0, hour: 0 };

        for (const ts of timestamps) {
            const date = new Date(ts);
            
            if (date.getMilliseconds() === 0) {
                alignments.second++;
            }
            if (date.getSeconds() === 0) {
                alignments.minute++;
            }
            if (date.getMinutes() === 0) {
                alignments.hour++;
            }
        }

        let alignment = null;
        let maxCount = 0;
        const threshold = timestamps.length * 0.3;

        for (const [type, count] of Object.entries(alignments)) {
            if (count > threshold && count > maxCount) {
                alignment = type;
                maxCount = count;
            }
        }

        return {
            aligned: alignment !== null,
            alignment,
            count: maxCount
        };
    }

    detectKnownAttacks(events) {
        const detectedAttacks = [];
        const actions = events.map(e => (e.action || e.endpoint || '').toLowerCase());
        const actionStr = actions.join('|');

        for (const [attackName, config] of Object.entries(this.knownAttackPatterns)) {
            const matches = actionStr.match(config.pattern);
            
            if (matches) {
                const matchingEvents = events.filter(e => 
                    config.pattern.test((e.action || e.endpoint || '').toLowerCase())
                );

                if (matchingEvents.length >= config.minRepetitions) {
                    const risk = this.calculateAttackRisk(attackName, matchingEvents, config);
                    
                    if (risk > 0.3) {
                        detectedAttacks.push({
                            type: 'attack',
                            attackName,
                            matchCount: matchingEvents.length,
                            risk,
                            config
                        });
                    }
                }
            }
        }

        return detectedAttacks;
    }

    calculateAttackRisk(attackName, events, config) {
        let baseRisk = events.length / (config.minRepetitions * 3);
        
        if (config.maxInterval) {
            const timestamps = events.map(e => e.timestamp);
            const intervals = [];
            for (let i = 1; i < timestamps.length; i++) {
                intervals.push(timestamps[i] - timestamps[i - 1]);
            }
            const avgInterval = MathUtils.mean(intervals);
            if (avgInterval < config.maxInterval) {
                baseRisk *= 1.2;
            }
        }

        if (config.sequentialIds) {
            const ids = events.map(e => e.targetId).filter(Boolean);
            if (this.areSequential(ids)) {
                baseRisk *= 1.3;
            }
        }

        baseRisk *= config.riskMultiplier;

        return MathUtils.clamp(baseRisk, 0, 1);
    }

    areSequential(values) {
        if (values.length < 3) return false;
        
        const numeric = values.map(Number).filter(n => !isNaN(n));
        if (numeric.length < 3) return false;

        let sequential = 0;
        for (let i = 1; i < numeric.length; i++) {
            if (Math.abs(numeric[i] - numeric[i - 1]) <= 1) {
                sequential++;
            }
        }

        return sequential / (numeric.length - 1) > 0.7;
    }

    detectAnomalousPatterns(events) {
        const patterns = [];

        const endpoints = events.map(e => e.endpoint);
        const endpointFreq = {};
        for (const ep of endpoints) {
            endpointFreq[ep] = (endpointFreq[ep] || 0) + 1;
        }

        const frequencies = Object.values(endpointFreq);
        const mean = MathUtils.mean(frequencies);
        const std = MathUtils.standardDeviation(frequencies);

        for (const [endpoint, count] of Object.entries(endpointFreq)) {
            const zScore = MathUtils.zScore(count, mean, std);
            if (zScore > 3) {
                patterns.push({
                    type: 'frequencyAnomaly',
                    endpoint,
                    count,
                    zScore,
                    risk: Math.min(zScore / 5, 1) * 0.7
                });
            }
        }

        const payloads = events.filter(e => e.payload).map(e => JSON.stringify(e.payload));
        const uniquePayloads = new Set(payloads).size;
        const payloadRepetition = 1 - (uniquePayloads / Math.max(payloads.length, 1));
        
        if (payloadRepetition > 0.8 && payloads.length > 10) {
            patterns.push({
                type: 'payloadRepetition',
                repetitionRate: payloadRepetition,
                risk: payloadRepetition * 0.5
            });
        }

        const ips = events.map(e => e.ip).filter(Boolean);
        if (new Set(ips).size > 1 && events.length > 5) {
            patterns.push({
                type: 'ipRotation',
                uniqueIps: new Set(ips).size,
                risk: Math.min(new Set(ips).size / 10, 1) * 0.6
            });
        }

        return patterns;
    }

    detectCoordinatedBehavior(events) {
        const patterns = [];
        
        const ips = events.map(e => e.ip).filter(Boolean);
        const userAgents = events.map(e => e.userAgent).filter(Boolean);
        
        if (new Set(ips).size > 1 && new Set(userAgents).size === 1 && events.length > 20) {
            patterns.push({
                type: 'coordinatedMultiIp',
                ipCount: new Set(ips).size,
                sharedUserAgent: true,
                risk: 0.7
            });
        }

        const timestamps = events.map(e => e.timestamp);
        const secondBuckets = new Map();
        
        for (const ts of timestamps) {
            const bucket = Math.floor(ts / 1000);
            secondBuckets.set(bucket, (secondBuckets.get(bucket) || 0) + 1);
        }

        for (const [bucket, count] of secondBuckets.entries()) {
            if (count > 20) {
                patterns.push({
                    type: 'coordinatedTiming',
                    timestamp: bucket * 1000,
                    concurrentRequests: count,
                    risk: Math.min(count / 50, 1) * 0.8
                });
            }
        }

        return patterns;
    }

    calculatePatternRisk(patterns) {
        if (patterns.length === 0) return 0;

        const risks = patterns.map(p => p.risk || 0);
        const maxRisk = Math.max(...risks);
        const avgRisk = MathUtils.mean(risks);
        const patternCountBonus = Math.min(patterns.length / 10, 0.2);

        return MathUtils.clamp(maxRisk * 0.6 + avgRisk * 0.3 + patternCountBonus, 0, 1);
    }

    identifyPrimaryAttack(attackPatterns) {
        if (attackPatterns.length === 0) return null;

        const sorted = attackPatterns.sort((a, b) => b.risk - a.risk);
        return sorted[0].attackName;
    }

    addCustomPattern(name, config) {
        this.knownAttackPatterns[name] = config;
    }

    removePattern(name) {
        delete this.knownAttackPatterns[name];
    }

    getPatternStats() {
        return {
            knownPatterns: Object.keys(this.knownAttackPatterns),
            suspiciousPatterns: Array.from(this.suspiciousPatterns.entries())
        };
    }
}

export default PatternDetector;
