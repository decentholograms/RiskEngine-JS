import MathUtils from './MathUtils.js';

class TimeSeriesAnalyzer {
    constructor(options = {}) {
        this.windowSize = options.windowSize || 50;
        this.seasonalPeriod = options.seasonalPeriod || 24;
        this.trendSensitivity = options.trendSensitivity || 0.1;
    }

    decompose(data) {
        if (data.length < this.seasonalPeriod * 2) {
            return { trend: data, seasonal: new Array(data.length).fill(0), residual: new Array(data.length).fill(0) };
        }

        const trend = this.calculateTrend(data);
        const detrended = data.map((v, i) => v - trend[i]);
        const seasonal = this.calculateSeasonal(detrended);
        const residual = data.map((v, i) => v - trend[i] - seasonal[i]);

        return { trend, seasonal, residual };
    }

    calculateTrend(data) {
        const trend = [];
        const halfWindow = Math.floor(this.windowSize / 2);

        for (let i = 0; i < data.length; i++) {
            const start = Math.max(0, i - halfWindow);
            const end = Math.min(data.length, i + halfWindow + 1);
            const window = data.slice(start, end);
            trend.push(MathUtils.mean(window));
        }

        return trend;
    }

    calculateSeasonal(detrended) {
        const seasonal = new Array(detrended.length).fill(0);
        const seasonalIndices = new Array(this.seasonalPeriod).fill(0).map(() => []);

        for (let i = 0; i < detrended.length; i++) {
            seasonalIndices[i % this.seasonalPeriod].push(detrended[i]);
        }

        const seasonalMeans = seasonalIndices.map(arr => MathUtils.mean(arr));
        const globalMean = MathUtils.mean(seasonalMeans);
        const adjustedMeans = seasonalMeans.map(m => m - globalMean);

        for (let i = 0; i < detrended.length; i++) {
            seasonal[i] = adjustedMeans[i % this.seasonalPeriod];
        }

        return seasonal;
    }

    detectAnomalies(data, sensitivity = 2) {
        const { residual } = this.decompose(data);
        const mean = MathUtils.mean(residual);
        const std = MathUtils.standardDeviation(residual);
        const anomalies = [];

        for (let i = 0; i < residual.length; i++) {
            const zScore = Math.abs(MathUtils.zScore(residual[i], mean, std));
            if (zScore > sensitivity) {
                anomalies.push({
                    index: i,
                    value: data[i],
                    zScore,
                    severity: this.calculateSeverity(zScore, sensitivity)
                });
            }
        }

        return anomalies;
    }

    calculateSeverity(zScore, threshold) {
        const excess = zScore - threshold;
        return MathUtils.clamp(excess / threshold, 0, 1);
    }

    detectChangePoints(data, minSize = 10) {
        if (data.length < minSize * 2) return [];

        const changePoints = [];
        
        for (let i = minSize; i < data.length - minSize; i++) {
            const before = data.slice(i - minSize, i);
            const after = data.slice(i, i + minSize);
            
            const meanBefore = MathUtils.mean(before);
            const meanAfter = MathUtils.mean(after);
            const stdBefore = MathUtils.standardDeviation(before);
            const stdAfter = MathUtils.standardDeviation(after);
            
            const pooledStd = Math.sqrt((stdBefore * stdBefore + stdAfter * stdAfter) / 2);
            const tStatistic = pooledStd > 0 ? Math.abs(meanAfter - meanBefore) / (pooledStd * Math.sqrt(2 / minSize)) : 0;
            
            if (tStatistic > 2.5) {
                changePoints.push({
                    index: i,
                    tStatistic,
                    meanBefore,
                    meanAfter,
                    direction: meanAfter > meanBefore ? 'increase' : 'decrease'
                });
            }
        }

        return this.mergeNearbyChangePoints(changePoints, minSize);
    }

    mergeNearbyChangePoints(points, minDistance) {
        if (points.length <= 1) return points;

        const merged = [points[0]];
        
        for (let i = 1; i < points.length; i++) {
            const last = merged[merged.length - 1];
            if (points[i].index - last.index < minDistance) {
                if (points[i].tStatistic > last.tStatistic) {
                    merged[merged.length - 1] = points[i];
                }
            } else {
                merged.push(points[i]);
            }
        }

        return merged;
    }

    forecast(data, steps = 10) {
        const { trend, seasonal } = this.decompose(data);
        const predictions = [];
        
        const recentTrend = trend.slice(-this.windowSize);
        const trendSlope = this.calculateSlope(recentTrend);
        const lastTrend = trend[trend.length - 1];

        for (let i = 0; i < steps; i++) {
            const trendValue = lastTrend + trendSlope * (i + 1);
            const seasonalIndex = (data.length + i) % this.seasonalPeriod;
            const seasonalValue = seasonal[seasonalIndex] || 0;
            predictions.push(trendValue + seasonalValue);
        }

        return predictions;
    }

    calculateSlope(data) {
        if (data.length < 2) return 0;
        
        const n = data.length;
        const xMean = (n - 1) / 2;
        const yMean = MathUtils.mean(data);
        
        let numerator = 0;
        let denominator = 0;
        
        for (let i = 0; i < n; i++) {
            numerator += (i - xMean) * (data[i] - yMean);
            denominator += (i - xMean) * (i - xMean);
        }
        
        return denominator !== 0 ? numerator / denominator : 0;
    }

    calculateVolatility(data, window = 20) {
        if (data.length < window) return 0;
        
        const returns = [];
        for (let i = 1; i < data.length; i++) {
            if (data[i - 1] !== 0) {
                returns.push((data[i] - data[i - 1]) / data[i - 1]);
            }
        }
        
        return MathUtils.standardDeviation(returns.slice(-window));
    }

    detectSeasonality(data) {
        if (data.length < 4) return { detected: false, period: 0 };

        const autocorrelations = [];
        const maxLag = Math.floor(data.length / 2);

        for (let lag = 1; lag < maxLag; lag++) {
            autocorrelations.push({
                lag,
                correlation: this.autocorrelation(data, lag)
            });
        }

        const peaks = [];
        for (let i = 1; i < autocorrelations.length - 1; i++) {
            if (autocorrelations[i].correlation > autocorrelations[i - 1].correlation &&
                autocorrelations[i].correlation > autocorrelations[i + 1].correlation &&
                autocorrelations[i].correlation > 0.3) {
                peaks.push(autocorrelations[i]);
            }
        }

        if (peaks.length === 0) {
            return { detected: false, period: 0, confidence: 0 };
        }

        const bestPeak = peaks.reduce((a, b) => a.correlation > b.correlation ? a : b);
        
        return {
            detected: true,
            period: bestPeak.lag,
            confidence: bestPeak.correlation
        };
    }

    autocorrelation(data, lag) {
        const n = data.length;
        const mean = MathUtils.mean(data);
        
        let numerator = 0;
        let denominator = 0;
        
        for (let i = 0; i < n - lag; i++) {
            numerator += (data[i] - mean) * (data[i + lag] - mean);
        }
        
        for (let i = 0; i < n; i++) {
            denominator += (data[i] - mean) * (data[i] - mean);
        }
        
        return denominator !== 0 ? numerator / denominator : 0;
    }

    detectTrend(data) {
        if (data.length < 3) return { trend: 'none', strength: 0 };

        const slope = this.calculateSlope(data);
        const normalizedSlope = slope / (MathUtils.mean(data) || 1);
        
        let trend = 'none';
        if (normalizedSlope > this.trendSensitivity) {
            trend = 'increasing';
        } else if (normalizedSlope < -this.trendSensitivity) {
            trend = 'decreasing';
        }

        return {
            trend,
            strength: Math.min(Math.abs(normalizedSlope) / this.trendSensitivity, 1),
            slope: normalizedSlope
        };
    }
}

export default TimeSeriesAnalyzer;
