class EntropyCalculator {
    static shannonEntropy(data) {
        if (!data || data.length === 0) return 0;
        
        const frequency = {};
        for (const item of data) {
            frequency[item] = (frequency[item] || 0) + 1;
        }
        
        const len = data.length;
        let entropy = 0;
        
        for (const count of Object.values(frequency)) {
            const probability = count / len;
            entropy -= probability * Math.log2(probability);
        }
        
        return entropy;
    }

    static stringEntropy(str) {
        if (!str) return 0;
        return this.shannonEntropy(str.split(''));
    }

    static normalizedEntropy(data) {
        if (!data || data.length <= 1) return 0;
        const uniqueCount = new Set(data).size;
        if (uniqueCount <= 1) return 0;
        const maxEntropy = Math.log2(uniqueCount);
        return this.shannonEntropy(data) / maxEntropy;
    }

    static conditionalEntropy(dataX, dataY) {
        if (dataX.length !== dataY.length) return 0;
        
        const jointFreq = {};
        const yFreq = {};
        
        for (let i = 0; i < dataX.length; i++) {
            const key = `${dataX[i]}|${dataY[i]}`;
            jointFreq[key] = (jointFreq[key] || 0) + 1;
            yFreq[dataY[i]] = (yFreq[dataY[i]] || 0) + 1;
        }
        
        let condEntropy = 0;
        const n = dataX.length;
        
        for (const [key, jointCount] of Object.entries(jointFreq)) {
            const y = key.split('|')[1];
            const pXY = jointCount / n;
            const pY = yFreq[y] / n;
            condEntropy -= pXY * Math.log2(pXY / pY);
        }
        
        return condEntropy;
    }

    static mutualInformation(dataX, dataY) {
        return this.shannonEntropy(dataX) - this.conditionalEntropy(dataX, dataY);
    }

    static relativeEntropy(p, q) {
        if (p.length !== q.length) return Infinity;
        
        let kl = 0;
        for (let i = 0; i < p.length; i++) {
            if (p[i] > 0 && q[i] > 0) {
                kl += p[i] * Math.log2(p[i] / q[i]);
            } else if (p[i] > 0) {
                return Infinity;
            }
        }
        return kl;
    }

    static jensenShannonDivergence(p, q) {
        const m = p.map((pi, i) => (pi + q[i]) / 2);
        return (this.relativeEntropy(p, m) + this.relativeEntropy(q, m)) / 2;
    }

    static timeSeriesEntropy(timestamps, windowSize = 10) {
        if (timestamps.length < 2) return 0;
        
        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }
        
        const buckets = this.bucketize(intervals, windowSize);
        return this.shannonEntropy(buckets);
    }

    static bucketize(values, numBuckets) {
        if (!values.length) return [];
        
        const min = Math.min(...values);
        const max = Math.max(...values);
        const range = max - min || 1;
        const bucketSize = range / numBuckets;
        
        return values.map(v => Math.floor((v - min) / bucketSize));
    }

    static approximateEntropy(data, m = 2, r = 0.2) {
        const n = data.length;
        if (n < m + 1) return 0;
        
        const std = this.standardDeviation(data);
        const tolerance = r * std;
        
        const phi = (m) => {
            const patterns = [];
            for (let i = 0; i <= n - m; i++) {
                patterns.push(data.slice(i, i + m));
            }
            
            let sum = 0;
            for (let i = 0; i < patterns.length; i++) {
                let count = 0;
                for (let j = 0; j < patterns.length; j++) {
                    const maxDiff = Math.max(
                        ...patterns[i].map((val, k) => Math.abs(val - patterns[j][k]))
                    );
                    if (maxDiff <= tolerance) count++;
                }
                sum += Math.log(count / patterns.length);
            }
            return sum / patterns.length;
        };
        
        return phi(m) - phi(m + 1);
    }

    static standardDeviation(arr) {
        const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
        const variance = arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
        return Math.sqrt(variance);
    }

    static sequenceComplexity(sequence) {
        if (!sequence || sequence.length === 0) return 0;
        
        const str = sequence.join(',');
        let complexity = 0;
        const seen = new Set();
        
        for (let len = 1; len <= str.length; len++) {
            for (let i = 0; i <= str.length - len; i++) {
                const substr = str.substring(i, i + len);
                if (!seen.has(substr)) {
                    seen.add(substr);
                    complexity++;
                }
            }
        }
        
        return complexity / str.length;
    }
}

export default EntropyCalculator;
