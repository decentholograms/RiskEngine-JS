class DeviceTracker {
    constructor(options = {}) {
        this.devices = new Map();
        this.userDevices = new Map();
        this.trustScores = new Map();
        this.maxDevicesPerUser = options.maxDevicesPerUser || 10;
        this.trustDecayRate = options.trustDecayRate || 0.01;
        this.trustBuildRate = options.trustBuildRate || 0.05;
    }

    registerDevice(userId, deviceInfo) {
        const deviceId = this.generateDeviceId(deviceInfo);
        const now = Date.now();

        let device = this.devices.get(deviceId);
        
        if (!device) {
            device = {
                id: deviceId,
                fingerprint: deviceInfo.fingerprint,
                userAgent: deviceInfo.userAgent,
                platform: deviceInfo.platform,
                browser: deviceInfo.browser,
                os: deviceInfo.os,
                screenResolution: deviceInfo.screenResolution,
                timezone: deviceInfo.timezone,
                language: deviceInfo.language,
                firstSeen: now,
                lastSeen: now,
                users: new Set(),
                trustScore: 0.5,
                activityCount: 0,
                flags: []
            };
            this.devices.set(deviceId, device);
        }

        device.lastSeen = now;
        device.activityCount++;
        device.users.add(userId);

        this.linkDeviceToUser(userId, deviceId);

        const analysis = this.analyzeDevice(device, userId);
        device.flags = analysis.flags;

        return {
            deviceId,
            device: this.sanitizeDevice(device),
            analysis,
            isNew: device.activityCount === 1
        };
    }

    generateDeviceId(deviceInfo) {
        const components = [
            deviceInfo.fingerprint,
            deviceInfo.userAgent,
            deviceInfo.platform,
            deviceInfo.screenResolution,
            deviceInfo.timezone
        ].filter(Boolean);

        return this.hash(components.join('|'));
    }

    hash(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) + hash) + str.charCodeAt(i);
        }
        return (hash >>> 0).toString(16);
    }

    linkDeviceToUser(userId, deviceId) {
        if (!this.userDevices.has(userId)) {
            this.userDevices.set(userId, {
                devices: [],
                primaryDevice: null,
                lastDeviceChange: 0
            });
        }

        const userRecord = this.userDevices.get(userId);
        
        const existingIndex = userRecord.devices.findIndex(d => d.deviceId === deviceId);
        
        if (existingIndex === -1) {
            userRecord.devices.push({
                deviceId,
                firstUsed: Date.now(),
                lastUsed: Date.now(),
                useCount: 1,
                trusted: false
            });

            if (userRecord.devices.length > this.maxDevicesPerUser) {
                userRecord.devices.sort((a, b) => a.lastUsed - b.lastUsed);
                userRecord.devices.shift();
            }
        } else {
            userRecord.devices[existingIndex].lastUsed = Date.now();
            userRecord.devices[existingIndex].useCount++;
        }

        if (!userRecord.primaryDevice) {
            const mostUsed = userRecord.devices.reduce((a, b) => 
                a.useCount > b.useCount ? a : b
            );
            userRecord.primaryDevice = mostUsed.deviceId;
        }
    }

    analyzeDevice(device, userId) {
        const flags = [];
        let riskScore = 0;

        if (device.users.size > 5) {
            flags.push({ type: 'shared_device', userCount: device.users.size });
            riskScore += 0.3;
        }

        if (device.users.size > 1) {
            const userRecord = this.userDevices.get(userId);
            if (userRecord) {
                const deviceRecord = userRecord.devices.find(d => d.deviceId === device.id);
                if (deviceRecord && deviceRecord.useCount === 1) {
                    flags.push({ type: 'first_use_shared_device' });
                    riskScore += 0.2;
                }
            }
        }

        const age = Date.now() - device.firstSeen;
        if (age < 300000 && device.activityCount > 10) {
            flags.push({ type: 'high_activity_new_device', age, activityCount: device.activityCount });
            riskScore += 0.4;
        }

        const uaParsed = this.parseUserAgent(device.userAgent);
        if (uaParsed.isBot) {
            flags.push({ type: 'bot_user_agent' });
            riskScore += 0.7;
        }
        if (uaParsed.isEmulator) {
            flags.push({ type: 'emulator_detected' });
            riskScore += 0.5;
        }

        if (device.platform && device.userAgent) {
            if (!this.platformMatchesUA(device.platform, device.userAgent)) {
                flags.push({ type: 'platform_mismatch' });
                riskScore += 0.4;
            }
        }

        return {
            flags,
            riskScore: Math.min(riskScore, 1),
            trustScore: device.trustScore
        };
    }

    parseUserAgent(ua) {
        if (!ua) return { isBot: true, isEmulator: false };

        const lowerUA = ua.toLowerCase();
        
        const botPatterns = [
            'bot', 'crawler', 'spider', 'scraper', 'headless',
            'phantom', 'selenium', 'puppeteer', 'playwright'
        ];

        const emulatorPatterns = [
            'android sdk', 'emulator', 'genymotion', 'simulator',
            'sdk_google', 'google_sdk'
        ];

        return {
            isBot: botPatterns.some(p => lowerUA.includes(p)),
            isEmulator: emulatorPatterns.some(p => lowerUA.includes(p))
        };
    }

    platformMatchesUA(platform, ua) {
        const lowerUA = ua.toLowerCase();
        const lowerPlatform = platform.toLowerCase();

        const platformMap = {
            'windows': ['windows', 'win32', 'win64'],
            'macos': ['mac', 'macintosh', 'darwin'],
            'linux': ['linux', 'x11'],
            'android': ['android'],
            'ios': ['iphone', 'ipad', 'ipod']
        };

        for (const [expected, patterns] of Object.entries(platformMap)) {
            if (patterns.some(p => lowerPlatform.includes(p))) {
                return patterns.some(p => lowerUA.includes(p));
            }
        }

        return true;
    }

    updateTrust(deviceId, positive = true) {
        const device = this.devices.get(deviceId);
        if (!device) return;

        if (positive) {
            device.trustScore = Math.min(1, device.trustScore + this.trustBuildRate);
        } else {
            device.trustScore = Math.max(0, device.trustScore - this.trustDecayRate * 5);
        }
    }

    trustDevice(userId, deviceId) {
        const userRecord = this.userDevices.get(userId);
        if (!userRecord) return false;

        const deviceRecord = userRecord.devices.find(d => d.deviceId === deviceId);
        if (deviceRecord) {
            deviceRecord.trusted = true;
            this.updateTrust(deviceId, true);
            return true;
        }

        return false;
    }

    untrustDevice(userId, deviceId) {
        const userRecord = this.userDevices.get(userId);
        if (!userRecord) return false;

        const deviceRecord = userRecord.devices.find(d => d.deviceId === deviceId);
        if (deviceRecord) {
            deviceRecord.trusted = false;
            this.updateTrust(deviceId, false);
            return true;
        }

        return false;
    }

    isDeviceTrusted(userId, deviceId) {
        const userRecord = this.userDevices.get(userId);
        if (!userRecord) return false;

        const deviceRecord = userRecord.devices.find(d => d.deviceId === deviceId);
        return deviceRecord?.trusted || false;
    }

    getUserDevices(userId) {
        const userRecord = this.userDevices.get(userId);
        if (!userRecord) return [];

        return userRecord.devices.map(d => {
            const device = this.devices.get(d.deviceId);
            return {
                ...d,
                details: device ? this.sanitizeDevice(device) : null
            };
        });
    }

    getDevice(deviceId) {
        const device = this.devices.get(deviceId);
        return device ? this.sanitizeDevice(device) : null;
    }

    sanitizeDevice(device) {
        return {
            id: device.id,
            platform: device.platform,
            browser: device.browser,
            os: device.os,
            screenResolution: device.screenResolution,
            timezone: device.timezone,
            firstSeen: device.firstSeen,
            lastSeen: device.lastSeen,
            trustScore: device.trustScore,
            activityCount: device.activityCount,
            flags: device.flags,
            sharedDevice: device.users.size > 1
        };
    }

    detectDeviceChange(userId, currentDeviceId) {
        const userRecord = this.userDevices.get(userId);
        if (!userRecord) return { changed: false };

        const previousPrimary = userRecord.primaryDevice;
        
        if (previousPrimary && previousPrimary !== currentDeviceId) {
            const previousDevice = this.devices.get(previousPrimary);
            const currentDevice = this.devices.get(currentDeviceId);

            const similarity = this.calculateDeviceSimilarity(previousDevice, currentDevice);

            return {
                changed: true,
                previousDeviceId: previousPrimary,
                similarity,
                suspicious: similarity < 0.3
            };
        }

        return { changed: false };
    }

    calculateDeviceSimilarity(device1, device2) {
        if (!device1 || !device2) return 0;

        let score = 0;
        let total = 0;

        const fields = ['platform', 'browser', 'os', 'timezone', 'language'];
        
        for (const field of fields) {
            total++;
            if (device1[field] === device2[field]) {
                score++;
            }
        }

        if (device1.screenResolution === device2.screenResolution) {
            score += 0.5;
        }
        total += 0.5;

        return score / total;
    }

    removeDevice(userId, deviceId) {
        const userRecord = this.userDevices.get(userId);
        if (!userRecord) return false;

        userRecord.devices = userRecord.devices.filter(d => d.deviceId !== deviceId);
        
        if (userRecord.primaryDevice === deviceId) {
            userRecord.primaryDevice = userRecord.devices.length > 0 
                ? userRecord.devices[0].deviceId 
                : null;
        }

        const device = this.devices.get(deviceId);
        if (device) {
            device.users.delete(userId);
            if (device.users.size === 0) {
                this.devices.delete(deviceId);
            }
        }

        return true;
    }

    getDeviceAnalytics(deviceId) {
        const device = this.devices.get(deviceId);
        if (!device) return null;

        const age = Date.now() - device.firstSeen;
        const activityRate = device.activityCount / (age / 3600000);

        return {
            device: this.sanitizeDevice(device),
            analytics: {
                ageHours: age / 3600000,
                activityPerHour: activityRate,
                uniqueUsers: device.users.size,
                riskIndicators: device.flags
            }
        };
    }

    getStats() {
        let trustedCount = 0;
        let flaggedCount = 0;

        for (const device of this.devices.values()) {
            if (device.trustScore > 0.7) trustedCount++;
            if (device.flags.length > 0) flaggedCount++;
        }

        return {
            totalDevices: this.devices.size,
            totalUserMappings: this.userDevices.size,
            trustedDevices: trustedCount,
            flaggedDevices: flaggedCount
        };
    }

    cleanup(maxAge = 2592000000) {
        const now = Date.now();

        for (const [deviceId, device] of this.devices.entries()) {
            if (now - device.lastSeen > maxAge) {
                for (const userId of device.users) {
                    this.removeDevice(userId, deviceId);
                }
            }
        }
    }
}

export default DeviceTracker;
