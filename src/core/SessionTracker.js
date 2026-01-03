class SessionTracker {
    constructor(options = {}) {
        this.sessions = new Map();
        this.userSessions = new Map();
        this.sessionTimeout = options.sessionTimeout || 1800000;
        this.maxSessionsPerUser = options.maxSessionsPerUser || 5;
        this.suspiciousThresholds = {
            rapidSessionCreation: options.rapidSessionCreation || 5,
            concurrentSessions: options.concurrentSessions || 3,
            geoVelocity: options.geoVelocity || 500
        };
        
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    }

    createSession(sessionId, data) {
        const now = Date.now();
        
        const session = {
            id: sessionId,
            userId: data.userId,
            ip: data.ip,
            userAgent: data.userAgent,
            geo: data.geo,
            fingerprint: data.fingerprint,
            createdAt: now,
            lastActivity: now,
            activityCount: 0,
            events: [],
            flags: [],
            riskScore: 0
        };

        this.sessions.set(sessionId, session);
        
        if (data.userId) {
            this.trackUserSession(data.userId, sessionId);
        }

        const analysis = this.analyzeNewSession(session);
        session.flags = analysis.flags;
        session.riskScore = analysis.riskScore;

        return {
            session,
            analysis
        };
    }

    trackUserSession(userId, sessionId) {
        if (!this.userSessions.has(userId)) {
            this.userSessions.set(userId, {
                sessions: [],
                sessionHistory: [],
                lastSessionCreated: 0
            });
        }

        const userRecord = this.userSessions.get(userId);
        userRecord.sessions.push({
            sessionId,
            createdAt: Date.now()
        });

        userRecord.lastSessionCreated = Date.now();

        if (userRecord.sessions.length > this.maxSessionsPerUser * 2) {
            userRecord.sessions = userRecord.sessions.slice(-this.maxSessionsPerUser * 2);
        }
    }

    analyzeNewSession(session) {
        const flags = [];
        let riskScore = 0;

        if (session.userId) {
            const userRecord = this.userSessions.get(session.userId);
            
            if (userRecord) {
                const recentSessions = userRecord.sessions.filter(
                    s => Date.now() - s.createdAt < 300000
                );
                
                if (recentSessions.length >= this.suspiciousThresholds.rapidSessionCreation) {
                    flags.push({ type: 'rapid_session_creation', count: recentSessions.length });
                    riskScore += 0.4;
                }

                const activeSessions = this.getActiveSessions(session.userId);
                if (activeSessions.length >= this.suspiciousThresholds.concurrentSessions) {
                    flags.push({ type: 'concurrent_sessions', count: activeSessions.length });
                    riskScore += 0.3;
                }

                const lastSession = this.getLastSession(session.userId, session.id);
                if (lastSession && lastSession.geo && session.geo) {
                    const velocity = this.calculateGeoVelocity(lastSession, session);
                    if (velocity > this.suspiciousThresholds.geoVelocity) {
                        flags.push({ type: 'impossible_travel', velocity });
                        riskScore += 0.6;
                    }
                }

                if (lastSession && lastSession.fingerprint !== session.fingerprint) {
                    flags.push({ type: 'fingerprint_change' });
                    riskScore += 0.2;
                }
            }
        }

        return {
            flags,
            riskScore: Math.min(riskScore, 1)
        };
    }

    getActiveSessions(userId) {
        const userRecord = this.userSessions.get(userId);
        if (!userRecord) return [];

        const now = Date.now();
        const activeSessions = [];

        for (const { sessionId } of userRecord.sessions) {
            const session = this.sessions.get(sessionId);
            if (session && now - session.lastActivity < this.sessionTimeout) {
                activeSessions.push(session);
            }
        }

        return activeSessions;
    }

    getLastSession(userId, excludeSessionId) {
        const userRecord = this.userSessions.get(userId);
        if (!userRecord) return null;

        for (let i = userRecord.sessions.length - 1; i >= 0; i--) {
            const { sessionId } = userRecord.sessions[i];
            if (sessionId !== excludeSessionId) {
                const session = this.sessions.get(sessionId);
                if (session) return session;
            }
        }

        return null;
    }

    calculateGeoVelocity(session1, session2) {
        if (!session1.geo || !session2.geo) return 0;
        if (!session1.geo.lat || !session2.geo.lat) return 0;

        const distance = this.haversineDistance(
            session1.geo.lat, session1.geo.lon,
            session2.geo.lat, session2.geo.lon
        );

        const timeDiff = Math.abs(session2.createdAt - session1.lastActivity) / 3600000;
        
        if (timeDiff === 0) return Infinity;
        
        return distance / timeDiff;
    }

    haversineDistance(lat1, lon1, lat2, lon2) {
        const R = 6371;
        const dLat = this.toRad(lat2 - lat1);
        const dLon = this.toRad(lon2 - lon1);
        
        const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                  Math.cos(this.toRad(lat1)) * Math.cos(this.toRad(lat2)) *
                  Math.sin(dLon / 2) * Math.sin(dLon / 2);
        
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        
        return R * c;
    }

    toRad(deg) {
        return deg * (Math.PI / 180);
    }

    recordActivity(sessionId, activity) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;

        const now = Date.now();
        
        session.lastActivity = now;
        session.activityCount++;
        
        session.events.push({
            type: activity.type || 'request',
            endpoint: activity.endpoint,
            timestamp: now,
            metadata: activity.metadata
        });

        if (session.events.length > 1000) {
            session.events = session.events.slice(-500);
        }

        const activityAnalysis = this.analyzeActivity(session);
        
        if (activityAnalysis.flags.length > 0) {
            session.flags = [...new Set([...session.flags, ...activityAnalysis.flags])];
            session.riskScore = Math.max(session.riskScore, activityAnalysis.riskScore);
        }

        return {
            session,
            activityAnalysis
        };
    }

    analyzeActivity(session) {
        const flags = [];
        let riskScore = 0;

        const recentEvents = session.events.filter(
            e => Date.now() - e.timestamp < 60000
        );

        if (recentEvents.length > 100) {
            flags.push({ type: 'high_activity_rate', eventsPerMinute: recentEvents.length });
            riskScore += 0.4;
        }

        const intervals = [];
        for (let i = 1; i < recentEvents.length; i++) {
            intervals.push(recentEvents[i].timestamp - recentEvents[i - 1].timestamp);
        }

        if (intervals.length > 10) {
            const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
            const variance = intervals.reduce((sum, i) => sum + Math.pow(i - mean, 2), 0) / intervals.length;
            const cv = Math.sqrt(variance) / mean;

            if (cv < 0.1) {
                flags.push({ type: 'robotic_timing', cv });
                riskScore += 0.5;
            }
        }

        const endpoints = recentEvents.map(e => e.endpoint);
        const uniqueEndpoints = new Set(endpoints).size;
        
        if (uniqueEndpoints === 1 && recentEvents.length > 20) {
            flags.push({ type: 'endpoint_hammering', endpoint: endpoints[0] });
            riskScore += 0.3;
        }

        return {
            flags,
            riskScore: Math.min(riskScore, 1)
        };
    }

    getSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;

        if (Date.now() - session.lastActivity > this.sessionTimeout) {
            this.invalidateSession(sessionId);
            return null;
        }

        return session;
    }

    invalidateSession(sessionId) {
        const session = this.sessions.get(sessionId);
        
        if (session && session.userId) {
            const userRecord = this.userSessions.get(session.userId);
            if (userRecord) {
                userRecord.sessions = userRecord.sessions.filter(s => s.sessionId !== sessionId);
                userRecord.sessionHistory.push({
                    sessionId,
                    invalidatedAt: Date.now(),
                    duration: Date.now() - session.createdAt,
                    activityCount: session.activityCount
                });

                if (userRecord.sessionHistory.length > 100) {
                    userRecord.sessionHistory = userRecord.sessionHistory.slice(-50);
                }
            }
        }

        this.sessions.delete(sessionId);
    }

    invalidateAllUserSessions(userId) {
        const activeSessions = this.getActiveSessions(userId);
        
        for (const session of activeSessions) {
            this.invalidateSession(session.id);
        }

        return activeSessions.length;
    }

    getSessionAnalytics(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;

        const now = Date.now();
        const duration = now - session.createdAt;
        const events = session.events;

        const endpointFrequency = {};
        for (const event of events) {
            endpointFrequency[event.endpoint] = (endpointFrequency[event.endpoint] || 0) + 1;
        }

        const intervals = [];
        for (let i = 1; i < events.length; i++) {
            intervals.push(events[i].timestamp - events[i - 1].timestamp);
        }

        return {
            sessionId: session.id,
            userId: session.userId,
            duration,
            activityCount: session.activityCount,
            averageInterval: intervals.length > 0 ? 
                intervals.reduce((a, b) => a + b, 0) / intervals.length : 0,
            endpointFrequency,
            topEndpoints: Object.entries(endpointFrequency)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5),
            flags: session.flags,
            riskScore: session.riskScore
        };
    }

    getUserAnalytics(userId) {
        const userRecord = this.userSessions.get(userId);
        if (!userRecord) return null;

        const activeSessions = this.getActiveSessions(userId);
        const history = userRecord.sessionHistory;

        const avgDuration = history.length > 0 ?
            history.reduce((sum, h) => sum + h.duration, 0) / history.length : 0;
        
        const avgActivityCount = history.length > 0 ?
            history.reduce((sum, h) => sum + h.activityCount, 0) / history.length : 0;

        return {
            userId,
            activeSessions: activeSessions.length,
            totalSessions: userRecord.sessions.length,
            historicalSessions: history.length,
            averageSessionDuration: avgDuration,
            averageActivityPerSession: avgActivityCount,
            lastSessionCreated: userRecord.lastSessionCreated,
            currentRisk: Math.max(...activeSessions.map(s => s.riskScore), 0)
        };
    }

    cleanup() {
        const now = Date.now();
        
        for (const [sessionId, session] of this.sessions.entries()) {
            if (now - session.lastActivity > this.sessionTimeout) {
                this.invalidateSession(sessionId);
            }
        }
    }

    getStats() {
        return {
            activeSessions: this.sessions.size,
            trackedUsers: this.userSessions.size,
            sessionsWithFlags: Array.from(this.sessions.values())
                .filter(s => s.flags.length > 0).length
        };
    }

    destroy() {
        clearInterval(this.cleanupInterval);
        this.sessions.clear();
        this.userSessions.clear();
    }
}

export default SessionTracker;
