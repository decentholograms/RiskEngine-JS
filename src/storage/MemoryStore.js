class MemoryStore {
    constructor(options = {}) {
        this.maxSize = options.maxSize || 100000;
        this.ttl = options.ttl || 3600000;
        this.cleanupInterval = options.cleanupInterval || 60000;
        this.store = new Map();
        this.expirations = new Map();
        this.stats = { hits: 0, misses: 0, evictions: 0 };
        
        this.cleanupTimer = setInterval(() => this.cleanup(), this.cleanupInterval);
    }

    set(key, value, ttl = this.ttl) {
        if (this.store.size >= this.maxSize) {
            this.evictOldest();
        }

        this.store.set(key, {
            value,
            createdAt: Date.now(),
            accessedAt: Date.now(),
            accessCount: 0
        });

        if (ttl > 0) {
            this.expirations.set(key, Date.now() + ttl);
        }

        return true;
    }

    get(key) {
        const entry = this.store.get(key);
        
        if (!entry) {
            this.stats.misses++;
            return null;
        }

        const expiration = this.expirations.get(key);
        if (expiration && Date.now() > expiration) {
            this.delete(key);
            this.stats.misses++;
            return null;
        }

        entry.accessedAt = Date.now();
        entry.accessCount++;
        this.stats.hits++;
        
        return entry.value;
    }

    has(key) {
        if (!this.store.has(key)) return false;
        
        const expiration = this.expirations.get(key);
        if (expiration && Date.now() > expiration) {
            this.delete(key);
            return false;
        }
        
        return true;
    }

    delete(key) {
        this.store.delete(key);
        this.expirations.delete(key);
        return true;
    }

    update(key, updater) {
        const current = this.get(key);
        if (current === null) return false;
        
        const updated = updater(current);
        return this.set(key, updated);
    }

    increment(key, field, amount = 1) {
        const current = this.get(key);
        if (current === null) return false;
        
        if (typeof current === 'object' && field) {
            current[field] = (current[field] || 0) + amount;
        } else if (typeof current === 'number') {
            this.set(key, current + amount);
            return current + amount;
        }
        
        return this.set(key, current);
    }

    push(key, value, maxLength = Infinity) {
        let arr = this.get(key);
        
        if (arr === null) {
            arr = [];
        }
        
        if (!Array.isArray(arr)) return false;
        
        arr.push(value);
        
        if (arr.length > maxLength) {
            arr = arr.slice(-maxLength);
        }
        
        return this.set(key, arr);
    }

    getWithMetadata(key) {
        const entry = this.store.get(key);
        if (!entry) return null;
        
        const expiration = this.expirations.get(key);
        if (expiration && Date.now() > expiration) {
            this.delete(key);
            return null;
        }
        
        return {
            value: entry.value,
            createdAt: entry.createdAt,
            accessedAt: entry.accessedAt,
            accessCount: entry.accessCount,
            ttlRemaining: expiration ? expiration - Date.now() : null
        };
    }

    keys(pattern = null) {
        const allKeys = Array.from(this.store.keys());
        
        if (!pattern) return allKeys;
        
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return allKeys.filter(key => regex.test(key));
    }

    values() {
        return Array.from(this.store.values()).map(entry => entry.value);
    }

    entries() {
        return Array.from(this.store.entries()).map(([key, entry]) => [key, entry.value]);
    }

    size() {
        return this.store.size;
    }

    clear() {
        this.store.clear();
        this.expirations.clear();
    }

    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [key, expiration] of this.expirations.entries()) {
            if (now > expiration) {
                this.delete(key);
                cleaned++;
            }
        }
        
        return cleaned;
    }

    evictOldest() {
        let oldestKey = null;
        let oldestAccess = Infinity;
        
        for (const [key, entry] of this.store.entries()) {
            if (entry.accessedAt < oldestAccess) {
                oldestAccess = entry.accessedAt;
                oldestKey = key;
            }
        }
        
        if (oldestKey) {
            this.delete(oldestKey);
            this.stats.evictions++;
        }
    }

    getStats() {
        const hitRate = this.stats.hits + this.stats.misses > 0 
            ? this.stats.hits / (this.stats.hits + this.stats.misses) 
            : 0;
            
        return {
            ...this.stats,
            hitRate,
            size: this.store.size,
            maxSize: this.maxSize
        };
    }

    destroy() {
        clearInterval(this.cleanupTimer);
        this.clear();
    }

    export() {
        const data = {};
        for (const [key, entry] of this.store.entries()) {
            data[key] = {
                value: entry.value,
                expiration: this.expirations.get(key)
            };
        }
        return JSON.stringify(data);
    }

    import(jsonData) {
        const data = JSON.parse(jsonData);
        const now = Date.now();
        
        for (const [key, entry] of Object.entries(data)) {
            if (!entry.expiration || entry.expiration > now) {
                this.store.set(key, {
                    value: entry.value,
                    createdAt: now,
                    accessedAt: now,
                    accessCount: 0
                });
                if (entry.expiration) {
                    this.expirations.set(key, entry.expiration);
                }
            }
        }
    }
}

export default MemoryStore;
