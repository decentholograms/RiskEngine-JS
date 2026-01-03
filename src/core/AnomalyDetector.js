class AnomalyDetector {
    constructor(options = {}) {
        this.sensitivity = options.sensitivity || 2.5;
        this.minSamples = options.minSamples || 30;
        this.contamination = options.contamination || 0.1;
        this.models = new Map();
    }

    train(identifier, data) {
        if (data.length < this.minSamples) {
            return { trained: false, reason: 'insufficient_data' };
        }

        const features = this.extractFeatures(data);
        const model = this.buildModel(features);
        
        this.models.set(identifier, model);
        
        return { trained: true, samples: data.length, features: Object.keys(features) };
    }

    extractFeatures(data) {
        const features = {};
        
        if (data.length > 0 && typeof data[0] === 'object') {
            const keys = Object.keys(data[0]).filter(k => typeof data[0][k] === 'number');
            
            for (const key of keys) {
                features[key] = data.map(d => d[key]).filter(v => v !== undefined && v !== null);
            }
        } else {
            features.value = data.filter(v => typeof v === 'number');
        }

        return features;
    }

    buildModel(features) {
        const model = {};

        for (const [name, values] of Object.entries(features)) {
            if (values.length < this.minSamples) continue;

            const sorted = [...values].sort((a, b) => a - b);
            const n = sorted.length;
            
            model[name] = {
                mean: values.reduce((a, b) => a + b, 0) / n,
                std: this.calculateStd(values),
                median: sorted[Math.floor(n / 2)],
                q1: sorted[Math.floor(n * 0.25)],
                q3: sorted[Math.floor(n * 0.75)],
                min: sorted[0],
                max: sorted[n - 1],
                iqr: sorted[Math.floor(n * 0.75)] - sorted[Math.floor(n * 0.25)]
            };
        }

        return model;
    }

    calculateStd(values) {
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
        return Math.sqrt(squaredDiffs.reduce((a, b) => a + b, 0) / values.length);
    }

    detect(identifier, sample) {
        const model = this.models.get(identifier);
        
        if (!model) {
            return { anomaly: false, reason: 'no_model', scores: {} };
        }

        const scores = {};
        const anomalies = [];
        let totalScore = 0;
        let count = 0;

        for (const [feature, stats] of Object.entries(model)) {
            const value = typeof sample === 'object' ? sample[feature] : sample;
            
            if (value === undefined || value === null) continue;

            const zScore = stats.std > 0 ? Math.abs(value - stats.mean) / stats.std : 0;
            const iqrScore = stats.iqr > 0 ? 
                Math.max(0, (value - stats.q3) / stats.iqr, (stats.q1 - value) / stats.iqr) : 0;
            
            const combinedScore = (zScore * 0.6 + iqrScore * 0.4);
            
            scores[feature] = {
                value,
                expected: stats.mean,
                zScore,
                iqrScore,
                combinedScore,
                isAnomaly: combinedScore > this.sensitivity
            };

            if (scores[feature].isAnomaly) {
                anomalies.push(feature);
            }

            totalScore += combinedScore;
            count++;
        }

        const avgScore = count > 0 ? totalScore / count : 0;
        const isAnomaly = avgScore > this.sensitivity || anomalies.length > count * this.contamination;

        return {
            anomaly: isAnomaly,
            score: avgScore,
            normalizedScore: Math.min(avgScore / (this.sensitivity * 2), 1),
            anomalousFeatures: anomalies,
            scores
        };
    }

    isolationForest(data, numTrees = 100, sampleSize = 256) {
        const trees = [];
        const n = data.length;
        const actualSampleSize = Math.min(sampleSize, n);

        for (let t = 0; t < numTrees; t++) {
            const sample = this.randomSample(data, actualSampleSize);
            const tree = this.buildIsolationTree(sample, 0, Math.ceil(Math.log2(actualSampleSize)));
            trees.push(tree);
        }

        return {
            trees,
            sampleSize: actualSampleSize,
            score: (point) => this.isolationScore(point, trees, actualSampleSize)
        };
    }

    randomSample(data, size) {
        const shuffled = [...data].sort(() => Math.random() - 0.5);
        return shuffled.slice(0, size);
    }

    buildIsolationTree(data, depth, maxDepth) {
        if (depth >= maxDepth || data.length <= 1) {
            return { type: 'leaf', size: data.length };
        }

        const features = Object.keys(data[0]).filter(k => typeof data[0][k] === 'number');
        if (features.length === 0) {
            return { type: 'leaf', size: data.length };
        }

        const feature = features[Math.floor(Math.random() * features.length)];
        const values = data.map(d => d[feature]).filter(v => v !== undefined);
        
        if (values.length === 0) {
            return { type: 'leaf', size: data.length };
        }

        const min = Math.min(...values);
        const max = Math.max(...values);

        if (min === max) {
            return { type: 'leaf', size: data.length };
        }

        const splitValue = min + Math.random() * (max - min);

        const left = data.filter(d => d[feature] < splitValue);
        const right = data.filter(d => d[feature] >= splitValue);

        return {
            type: 'node',
            feature,
            splitValue,
            left: this.buildIsolationTree(left, depth + 1, maxDepth),
            right: this.buildIsolationTree(right, depth + 1, maxDepth)
        };
    }

    pathLength(point, tree, depth = 0) {
        if (tree.type === 'leaf') {
            return depth + this.averagePathLength(tree.size);
        }

        const value = point[tree.feature];
        if (value === undefined) {
            return depth + this.averagePathLength(1);
        }

        if (value < tree.splitValue) {
            return this.pathLength(point, tree.left, depth + 1);
        } else {
            return this.pathLength(point, tree.right, depth + 1);
        }
    }

    averagePathLength(n) {
        if (n <= 1) return 0;
        if (n === 2) return 1;
        return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
    }

    isolationScore(point, trees, sampleSize) {
        const avgPath = trees.reduce((sum, tree) => sum + this.pathLength(point, tree), 0) / trees.length;
        const c = this.averagePathLength(sampleSize);
        return Math.pow(2, -avgPath / c);
    }

    localOutlierFactor(data, k = 5) {
        const n = data.length;
        const distances = this.computeDistanceMatrix(data);
        const lofs = [];

        for (let i = 0; i < n; i++) {
            const kNeighbors = this.getKNearestNeighbors(distances[i], k, i);
            const lrd = this.localReachabilityDensity(i, kNeighbors, distances, k);
            
            let lof = 0;
            for (const neighbor of kNeighbors) {
                const neighborKNeighbors = this.getKNearestNeighbors(distances[neighbor], k, neighbor);
                const neighborLrd = this.localReachabilityDensity(neighbor, neighborKNeighbors, distances, k);
                lof += neighborLrd / lrd;
            }
            lof /= k;
            
            lofs.push({ index: i, lof, isOutlier: lof > 1.5 });
        }

        return lofs;
    }

    computeDistanceMatrix(data) {
        const n = data.length;
        const matrix = Array(n).fill(null).map(() => Array(n).fill(0));

        for (let i = 0; i < n; i++) {
            for (let j = i + 1; j < n; j++) {
                const dist = this.euclideanDistance(data[i], data[j]);
                matrix[i][j] = dist;
                matrix[j][i] = dist;
            }
        }

        return matrix;
    }

    euclideanDistance(a, b) {
        const keys = Object.keys(a).filter(k => typeof a[k] === 'number' && typeof b[k] === 'number');
        let sum = 0;
        for (const key of keys) {
            sum += Math.pow(a[key] - b[key], 2);
        }
        return Math.sqrt(sum);
    }

    getKNearestNeighbors(distances, k, excludeIndex) {
        const indexed = distances.map((d, i) => ({ index: i, distance: d }));
        indexed.splice(excludeIndex, 1);
        indexed.sort((a, b) => a.distance - b.distance);
        return indexed.slice(0, k).map(x => x.index);
    }

    localReachabilityDensity(pointIndex, neighbors, distances, k) {
        let sum = 0;
        for (const neighbor of neighbors) {
            const reachDist = Math.max(
                distances[neighbor][this.getKNearestNeighbors(distances[neighbor], k, neighbor)[k - 1]],
                distances[pointIndex][neighbor]
            );
            sum += reachDist;
        }
        return neighbors.length / sum;
    }

    detectSeasonalAnomaly(data, period) {
        if (data.length < period * 2) {
            return { detected: false, reason: 'insufficient_data' };
        }

        const seasonal = [];
        const residuals = [];

        for (let i = 0; i < period; i++) {
            const seasonalValues = [];
            for (let j = i; j < data.length; j += period) {
                seasonalValues.push(data[j]);
            }
            seasonal[i] = seasonalValues.reduce((a, b) => a + b, 0) / seasonalValues.length;
        }

        for (let i = 0; i < data.length; i++) {
            residuals.push(data[i] - seasonal[i % period]);
        }

        const mean = residuals.reduce((a, b) => a + b, 0) / residuals.length;
        const std = this.calculateStd(residuals);

        const anomalies = [];
        for (let i = 0; i < residuals.length; i++) {
            const zScore = Math.abs(residuals[i] - mean) / std;
            if (zScore > this.sensitivity) {
                anomalies.push({
                    index: i,
                    value: data[i],
                    expected: seasonal[i % period],
                    residual: residuals[i],
                    zScore
                });
            }
        }

        return {
            detected: anomalies.length > 0,
            anomalies,
            seasonal,
            residualStats: { mean, std }
        };
    }

    getModel(identifier) {
        return this.models.get(identifier);
    }

    clearModel(identifier) {
        this.models.delete(identifier);
    }

    clearAllModels() {
        this.models.clear();
    }
}

export default AnomalyDetector;
