# RiskEngine-JS 🛡️⚡

**Advanced Behavior-Based Anti-Abuse & Anti-Cheat Engine for JavaScript Applications**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/yourusername/RiskEngine-JS/blob/main/LICENSE)
[![JavaScript Version](https://img.shields.io/badge/javascript-%3E%3D4.0-blue)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0-green)](https://nodejs.org/)
[![Stars](https://img.shields.io/github/stars/yourusername/RiskEngine-JS?style=social)](https://github.com/yourusername/RiskEngine-JS/stargazers)
[![Contributors](https://img.shields.io/github/contributors/yourusername/RiskEngine-JS)](https://github.com/yourusername/RiskEngine-JS/graphs/contributors)

---

## 🚀 **Overview**

RiskEngine-JS is a **cutting-edge behavior-based security system** designed to protect your web applications, APIs, and real-time systems from abuse, cheating, and automated attacks. By analyzing user behavior patterns using **statistical analysis, anomaly detection, and machine learning techniques**, RiskEngine dynamically calculates risk scores and applies **adaptive mitigation strategies** to keep your platform secure.

### **Key Features**
✅ **Multi-layered Risk Scoring** – Combines behavior analysis, pattern detection, rate limiting, and device fingerprinting
✅ **Adaptive Mitigation** – Automatically adjusts to new threats with configurable risk thresholds
✅ **Real-time Protection** – Integrates seamlessly with Express.js and other web frameworks
✅ **Behavior Profiling** – Detects anomalies in user interaction patterns
✅ **Device & Session Tracking** – Identifies suspicious device behavior and session anomalies
✅ **Rate Limiting & Throttling** – Prevents brute-force attacks and API abuse
✅ **Bot & Automation Detection** – Uses entropy analysis and fingerprinting to detect bots
✅ **Threat Intelligence Integration** – Built-in blacklists for known malicious patterns
✅ **Extensible Architecture** – Modular design for easy customization and integration

### **Who Is This For?**
- **Web Application Developers** – Protect your apps from automated attacks
- **API Providers** – Secure your endpoints with dynamic rate limiting
- **E-commerce Platforms** – Prevent fraud and payment abuse
- **Gaming Developers** – Detect and block cheating in real-time
- **Social Media & Community Sites** – Prevent spam and abuse
- **Security Teams** – Add an extra layer of protection to your infrastructure

---

## ✨ **Features in Detail**

### **1. Advanced Behavior Analysis**
- **Statistical Anomaly Detection** – Identifies unusual user behavior patterns
- **Entropy-Based Automation Detection** – Detects scripted interactions
- **Time-Series Analysis** – Analyzes user activity rhythms and sequences

### **2. Pattern Detection Engine**
- **Brute Force Detection** – Blocks repeated login attempts
- **API Abuse Prevention** – Limits excessive API calls
- **Scraping & Crawling Detection** – Identifies automated data harvesting
- **Account Takeover Prevention** – Detects suspicious password reset patterns

### **3. Rate Limiting & Throttling**
- **Adaptive Rate Limiting** – Adjusts limits based on user behavior
- **Burst Protection** – Prevents sudden spikes in requests
- **Penalty & Reward System** – Penalizes abusive users while rewarding good ones

### **4. Device & Session Tracking**
- **Device Fingerprinting** – Creates unique device signatures
- **Session Anomaly Detection** – Identifies suspicious session behavior
- **Device Trust Scoring** – Ranks devices based on trustworthiness

### **5. Threat Intelligence**
- **Bot User-Agent Blacklist** – Blocks known bots
- **Suspicious Pattern Detection** – Flags malicious payloads
- **Geo & ASN Risk Scoring** – Assesses risk based on location and network

### **6. Middleware Integration**
- **Express.js Middleware** – Easy integration with your existing apps
- **Customizable Risk Decisions** – Define your own mitigation strategies
- **Real-time Risk Headers** – Pass risk scores to your application

---

## 🛠️ **Tech Stack**

| Category          | Technologies Used                          |
|-------------------|--------------------------------------------|
| **Language**      | JavaScript (ES6+)                          |
| **Framework**     | Express.js (for middleware integration)   |
| **Dependencies**  | `uuid` (for generating unique identifiers)|
| **Data Storage**  | In-memory storage (with TTL support)      |
| **Math Libraries**| Custom statistical and entropy calculators |

### **System Requirements**
- **Node.js** ≥ 14.0
- **npm** or **yarn** for package management
- **Express.js** (for middleware integration)


## 📦 **Installation**

### **Prerequisites**
Ensure you have Node.js installed:
```bash
node -v  # Should be ≥ 14.0
npm -v   # Should be ≥ 6.0
```

### **Quick Start**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/RiskEngine-JS.git
   cd RiskEngine-JS
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Run the demo server:**
   ```bash
   npm start
   ```
   The server will start on `http://localhost:3000`.

4. **Access the demo endpoints:**
   - `/health` – Health check endpoint
   - `/metrics` – Risk engine statistics
   - `/api/users` – Example protected endpoint

### **Alternative Installation Methods**

#### **Using npm/yarn (Recommended)**
```bash
npm install risk-engine-js
# or
yarn add risk-engine-js
```

#### **Docker Setup (Coming Soon)**
We plan to provide a Docker image for easy deployment in containerized environments.

#### **Development Setup**
For contributing to the project:
```bash
git clone https://github.com/yourusername/RiskEngine-JS.git
cd RiskEngine-JS
npm install --dev
npm run dev  # Runs with watch mode for development
```

---

## 🎯 **Usage Examples**

### **1. Basic Integration with Express.js**
```javascript
import express from 'express';
import { RiskEngine } from 'risk-engine-js';
import createAntiAbuseMiddleware from 'risk-engine-js/middleware/antiAbuse';

const app = express();
const PORT = 3000;

// Initialize RiskEngine with custom thresholds
const riskEngine = new RiskEngine({
  thresholds: {
    low: 0.25,
    medium: 0.5,
    high: 0.7,
    critical: 0.9
  },
  weights: {
    behavior: 0.25,
    patterns: 0.25,
    rateLimit: 0.2,
    fingerprint: 0.15,
    reputation: 0.15
  },
  onHighRisk: (decision) => {
    console.log(`[ALERT] High risk detected for user ${decision.userId}: ${decision.riskScore.toFixed(3)}`);
  }
});

// Create anti-abuse middleware
const antiAbuse = createAntiAbuseMiddleware({
  engine: riskEngine,
  trustProxy: true,
  skipPaths: ['/health', '/metrics'],
  onDecision: (decision, req, res) => {
    if (decision.riskScore > 0.5) {
      console.log(`[RISK] ${req.method} ${req.path} - Score: ${decision.riskScore.toFixed(3)}`);
    }
  }
});

// Apply middleware to all routes
app.use(antiAbuse);

// Example protected route
app.get('/api/users', (req, res) => {
  res.json({
    users: [{ id: 1, name: 'User 1' }],
    riskDecision: req.riskDecision ? {
      score: req.riskDecision.riskScore,
      level: req.riskDecision.riskLevel
    } : null
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
```

### **2. Evaluating a User's Risk Score**
```javascript
import { RiskEngine } from 'risk-engine-js';

const riskEngine = new RiskEngine();

// Simulate a request object
const request = {
  ip: '192.168.1.1',
  userId: 'user123',
  method: 'GET',
  path: '/api/users',
  headers: {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
  }
};

// Evaluate the risk
async function evaluateRisk() {
  const decision = await riskEngine.evaluate(request);
  console.log('Risk Decision:', decision);
  // Output: { riskScore: 0.12, riskLevel: 'low', action: { type: 'allow' } }
}

evaluateRisk();
```

### **3. Customizing Risk Thresholds**
```javascript
const riskEngine = new RiskEngine({
  thresholds: {
    low: 0.3,    // Allow users with risk < 0.3
    medium: 0.6, // Challenge users with risk between 0.3 and 0.6
    high: 0.8,   // Throttle users with risk between 0.6 and 0.8
    critical: 0.9 // Block users with risk ≥ 0.9
  },
  weights: {
    behavior: 0.3,    // Increase weight for behavior analysis
    patterns: 0.2,    // Decrease weight for pattern detection
    rateLimit: 0.25,  // Increase weight for rate limiting
    fingerprint: 0.15, // Keep fingerprint weight the same
    reputation: 0.1   // Decrease weight for reputation
  }
});
```

---

## 📁 **Project Structure**

```
RiskEngine-JS/
├── src/
│   ├── core/               # Core risk analysis components
│   │   ├── RiskEngine.js    # Main risk engine class
│   │   ├── BehaviorAnalyzer.js
│   │   ├── PatternDetector.js
│   │   ├── RateLimiter.js
│   │   ├── Fingerprinter.js
│   │   ├── AnomalyDetector.js
│   │   ├── ThreatIntelligence.js
│   │   ├── SessionTracker.js
│   │   └── VelocityChecker.js
│   ├── middleware/         # Express middleware
│   │   └── antiAbuse.js
│   ├── storage/            # Data storage implementations
│   │   └── MemoryStore.js
│   ├── utils/              # Utility functions
│   │   ├── MathUtils.js
│   │   ├── EntropyCalculator.js
│   │   └── TimeSeriesAnalyzer.js
│   └── index.js            # Main exports
├── server.js               # Demo server
├── test/                   # Test files
├── package.json
├── README.md               # This file
└── LICENSE                 # MIT License
```

---

## 🔧 **Configuration**

### **Environment Variables**
RiskEngine-JS can be configured via environment variables for easy deployment:

| Variable               | Description                                      | Default Value |
|------------------------|--------------------------------------------------|---------------|
| `RISK_ENGINE_THRESHOLDS` | JSON string for risk thresholds                 | `{ "low": 0.3, "medium": 0.5, "high": 0.7, "critical": 0.9 }` |
| `RISK_ENGINE_WEIGHTS`    | JSON string for risk factor weights              | `{ "behavior": 0.25, "patterns": 0.25, "rateLimit": 0.2, "fingerprint": 0.15, "reputation": 0.15 }` |
| `RISK_ENGINE_RATE_LIMIT` | JSON string for rate limiting settings           | `{ "defaultLimit": 100, "windowSize": 60000, "burstMultiplier": 2 }` |

Example:
```bash
export RISK_ENGINE_THRESHOLDS='{"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 0.95}'
export RISK_ENGINE_WEIGHTS='{"behavior": 0.3, "patterns": 0.2, "rateLimit": 0.3, "fingerprint": 0.15, "reputation": 0.05}'
```

### **Customizing Risk Decisions**
You can define custom actions based on risk scores:

```javascript
const riskEngine = new RiskEngine({
  actions: {
    allow: { maxScore: 0.4 },          // Allow users with risk < 0.4
    challenge: { minScore: 0.4, maxScore: 0.6 }, // Challenge users with risk between 0.4 and 0.6
    throttle: { minScore: 0.6, maxScore: 0.8 }, // Throttle users with risk between 0.6 and 0.8
    block: { minScore: 0.8, maxScore: 0.95 }, // Block users with risk between 0.8 and 0.95
    ban: { minScore: 0.95 }             // Ban users with risk ≥ 0.95
  }
});
```

---

## 🤝 **Contributing**

We welcome contributions from the community! Here's how you can get involved:

### **How to Contribute**
1. **Fork the repository** and clone it locally.
2. **Create a new branch** for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** and ensure they follow the project's coding standards.
4. **Write tests** for your changes (if applicable).
5. **Commit your changes** with a clear message:
   ```bash
   git commit -m "feat: add new pattern detection for scraping"
   ```
6. **Push to your fork** and open a **Pull Request** to the `main` branch.

### **Development Setup**
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/RiskEngine-JS.git
   cd RiskEngine-JS
   ```
2. Install development dependencies:
   ```bash
   npm install --dev
   ```
3. Run the development server with watch mode:
   ```bash
   npm run dev
   ```
4. Run tests:
   ```bash
   npm test
   ```

### **Code Style Guidelines**
- Use **ES6+ JavaScript** features.
- Follow **consistent indentation** (2 spaces).
- Write **clear, concise comments** for complex logic.
- Ensure **code is well-structured** and modular.
- Use **JSDoc** for function and class documentation.

### **Pull Request Process**
1. Ensure your PR description clearly explains the changes.
2. Reference any related issues or tickets.
3. Include screenshots or examples if applicable.
4. Be open to feedback and willing to iterate on your changes.

---

## 📝 **License**

RiskEngine-JS is released under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 👥 **Authors & Contributors**

### **Maintainers**
- **Frannn** – [@frannn](https://github.com/frannn) (Initial development)

### **Contributors**
A huge thank you to all the contributors who have helped improve RiskEngine-JS:
- [Contributors List](https://github.com/yourusername/RiskEngine-JS/graphs/contributors)

### **Acknowledgments**
- Inspired by **statistical anomaly detection** techniques from machine learning research.
- Built with **Express.js** for middleware integration.
- Uses **custom utility libraries** for mathematical and statistical calculations.

---

## 🐛 **Issues & Support**

### **Reporting Issues**
If you encounter a bug or have a feature request, please:
1. Check the [GitHub Issues](https://github.com/yourusername/RiskEngine-JS/issues) for existing discussions.
2. Open a new issue with a clear title and description.
3. Include **reproducible steps**, **error logs**, and **expected behavior**.

### **Getting Help**
- **Discussions**: Join our [GitHub Discussions](https://github.com/yourusername/RiskEngine-JS/discussions) for general questions.
- **Community**: Reach out to us on [Twitter](https://twitter.com/yourhandle) or [Slack](https://your-slack-invite-link).
- **Email**: For urgent support, email **support@riskengine-js.com**.

### **FAQ**
**Q: Can I use RiskEngine-JS in production?**
A: Yes! RiskEngine-JS is designed for production use and has been tested with real-world traffic.

**Q: Does RiskEngine-JS support clustering or distributed environments?**
A: Currently, RiskEngine-JS uses an in-memory store. For distributed environments, consider using Redis or another shared storage solution.

**Q: How do I customize the risk factors?**
A: You can adjust the weights for each risk factor in the `weights` configuration object.

**Q: Does RiskEngine-JS integrate with other frameworks?**
A: While RiskEngine-JS is designed for Express.js, you can extract the core logic and integrate it with other frameworks.

---

## 🗺️ **Roadmap**

### **Planned Features**
- **[In Progress]** Redis integration for distributed environments
- **[Planned]** Machine learning model integration (e.g., TensorFlow.js)
- **[Planned]** GraphQL middleware support
- **[Planned]** Advanced threat intelligence feeds (e.g., AbuseIPDB, VirusTotal)
- **[Planned]** Docker and Kubernetes deployment guides

### **Known Issues**
- **Issue #1**: Some pattern detection rules may produce false positives in certain scenarios.
- **Issue #2**: Memory store may not be suitable for high-traffic applications (Redis integration will address this).

### **Future Improvements**
- **Enhanced Bot Detection**: Add more sophisticated bot detection techniques.
- **Behavior Learning**: Allow the engine to learn and adapt to new user behaviors over time.
- **Performance Optimizations**: Reduce latency for high-throughput applications.

---

## 🚀 **Get Started Today!**

RiskEngine-JS is your **first line of defense** against abuse, cheating, and automated attacks. Whether you're protecting a web app, API, or gaming platform, RiskEngine provides **real-time, adaptive security** that grows with your application.

🔗 **[GitHub Repository](https://github.com/yourusername/RiskEngine-JS)**
📦 **[npm Package](https://www.npmjs.com/package/risk-engine-js)**
💬 **[Join the Discussion](https://github.com/yourusername/RiskEngine-JS/discussions)**

**Let's build a safer web together!** 🛡️
```
