class MathUtils {
    static mean(arr) {
        if (!arr.length) return 0;
        return arr.reduce((a, b) => a + b, 0) / arr.length;
    }

    static variance(arr) {
        if (arr.length < 2) return 0;
        const m = this.mean(arr);
        return arr.reduce((acc, val) => acc + Math.pow(val - m, 2), 0) / (arr.length - 1);
    }

    static standardDeviation(arr) {
        return Math.sqrt(this.variance(arr));
    }

    static zScore(value, mean, stdDev) {
        if (stdDev === 0) return 0;
        return (value - mean) / stdDev;
    }

    static median(arr) {
        if (!arr.length) return 0;
        const sorted = [...arr].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    static percentile(arr, p) {
        if (!arr.length) return 0;
        const sorted = [...arr].sort((a, b) => a - b);
        const index = (p / 100) * (sorted.length - 1);
        const lower = Math.floor(index);
        const upper = Math.ceil(index);
        if (lower === upper) return sorted[lower];
        return sorted[lower] * (upper - index) + sorted[upper] * (index - lower);
    }

    static iqr(arr) {
        return this.percentile(arr, 75) - this.percentile(arr, 25);
    }

    static isOutlier(value, arr, threshold = 1.5) {
        const q1 = this.percentile(arr, 25);
        const q3 = this.percentile(arr, 75);
        const iqr = q3 - q1;
        return value < q1 - threshold * iqr || value > q3 + threshold * iqr;
    }

    static covariance(arr1, arr2) {
        if (arr1.length !== arr2.length || arr1.length < 2) return 0;
        const mean1 = this.mean(arr1);
        const mean2 = this.mean(arr2);
        let sum = 0;
        for (let i = 0; i < arr1.length; i++) {
            sum += (arr1[i] - mean1) * (arr2[i] - mean2);
        }
        return sum / (arr1.length - 1);
    }

    static correlation(arr1, arr2) {
        const cov = this.covariance(arr1, arr2);
        const std1 = this.standardDeviation(arr1);
        const std2 = this.standardDeviation(arr2);
        if (std1 === 0 || std2 === 0) return 0;
        return cov / (std1 * std2);
    }

    static exponentialMovingAverage(arr, alpha = 0.3) {
        if (!arr.length) return 0;
        let ema = arr[0];
        for (let i = 1; i < arr.length; i++) {
            ema = alpha * arr[i] + (1 - alpha) * ema;
        }
        return ema;
    }

    static sigmoid(x) {
        return 1 / (1 + Math.exp(-x));
    }

    static softmax(arr) {
        const maxVal = Math.max(...arr);
        const exps = arr.map(x => Math.exp(x - maxVal));
        const sumExps = exps.reduce((a, b) => a + b, 0);
        return exps.map(exp => exp / sumExps);
    }

    static euclideanDistance(arr1, arr2) {
        if (arr1.length !== arr2.length) return Infinity;
        let sum = 0;
        for (let i = 0; i < arr1.length; i++) {
            sum += Math.pow(arr1[i] - arr2[i], 2);
        }
        return Math.sqrt(sum);
    }

    static cosineSimilarity(arr1, arr2) {
        if (arr1.length !== arr2.length) return 0;
        let dotProduct = 0;
        let norm1 = 0;
        let norm2 = 0;
        for (let i = 0; i < arr1.length; i++) {
            dotProduct += arr1[i] * arr2[i];
            norm1 += arr1[i] * arr1[i];
            norm2 += arr2[i] * arr2[i];
        }
        if (norm1 === 0 || norm2 === 0) return 0;
        return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
    }

    static normalize(arr, min = 0, max = 1) {
        const minVal = Math.min(...arr);
        const maxVal = Math.max(...arr);
        if (maxVal === minVal) return arr.map(() => (max + min) / 2);
        return arr.map(x => min + (x - minVal) * (max - min) / (maxVal - minVal));
    }

    static clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    static lerp(a, b, t) {
        return a + (b - a) * t;
    }

    static smoothstep(edge0, edge1, x) {
        const t = this.clamp((x - edge0) / (edge1 - edge0), 0, 1);
        return t * t * (3 - 2 * t);
    }
}

export default MathUtils;
