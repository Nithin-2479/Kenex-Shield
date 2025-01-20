class LogClassifier {
    constructor() {
        // Patterns for different types of malicious activities
        this.patterns = {
            firewall: {
                malicious: [
                    /bruteforce/i,
                    /blocked\s+ip/i,
                    /port\s+scan/i,
                    /ddos/i,
                    /exploit\s+attempt/i
                ],
                severity: {
                    high: /critical|emergency|alert/i,
                    medium: /warning|blocked/i,
                    low: /notice|info/i
                }
            },
            dns: {
                malicious: [
                    /malware\s+domain/i,
                    /phishing/i,
                    /suspicious\s+dns/i,
                    /blocked\s+domain/i,
                    /dns\s+tunneling/i
                ],
                severity: {
                    high: /malware|c2|command\s+and\s+control/i,
                    medium: /suspicious|blocked/i,
                    low: /cached|resolved/i
                }
            },
            user: {
                malicious: [
                    /failed\s+login/i,
                    /privilege\s+escalation/i,
                    /unauthorized\s+access/i,
                    /password\s+spray/i,
                    /account\s+lockout/i
                ],
                severity: {
                    high: /privilege|unauthorized/i,
                    medium: /failed\s+login|lockout/i,
                    low: /logout|password\s+changed/i
                }
            }
        };
    }

    analyzeLogs(logs, type) {
        const results = {
            totalLogs: logs.length,
            maliciousCount: 0,
            severityDistribution: {
                high: 0,
                medium: 0,
                low: 0
            },
            topThreats: {},
            timeBasedAnalysis: {},
            recommendations: []
        };

        logs.forEach(log => {
            // Check for malicious patterns
            const isMalicious = this.patterns[type].malicious.some(pattern => 
                pattern.test(log.message)
            );

            if (isMalicious) {
                results.maliciousCount++;
                
                // Determine severity
                if (this.patterns[type].severity.high.test(log.message)) {
                    results.severityDistribution.high++;
                } else if (this.patterns[type].severity.medium.test(log.message)) {
                    results.severityDistribution.medium++;
                } else {
                    results.severityDistribution.low++;
                }

                // Track threats
                const threat = this.identifyThreat(log.message);
                results.topThreats[threat] = (results.topThreats[threat] || 0) + 1;
            }

            // Time-based analysis
            const hour = new Date(log.timestamp).getHours();
            results.timeBasedAnalysis[hour] = (results.timeBasedAnalysis[hour] || 0) + 1;
        });

        // Generate recommendations
        results.recommendations = this.generateRecommendations(results, type);

        return results;
    }

    identifyThreat(message) {
        // Simple threat identification logic
        if (message.match(/bruteforce|password\s+spray/i)) return 'Brute Force Attack';
        if (message.match(/ddos|flood/i)) return 'DDoS Attack';
        if (message.match(/malware|virus/i)) return 'Malware';
        if (message.match(/phishing/i)) return 'Phishing';
        if (message.match(/port\s+scan/i)) return 'Port Scanning';
        return 'Other';
    }

    generateRecommendations(results, type) {
        const recommendations = [];
        const maliciousPercentage = (results.maliciousCount / results.totalLogs) * 100;

        if (maliciousPercentage > 10) {
            recommendations.push('High percentage of malicious activity detected. Consider reviewing security policies.');
        }

        if (results.severityDistribution.high > 0) {
            recommendations.push('Critical security events detected. Immediate investigation recommended.');
        }

        switch (type) {
            case 'firewall':
                if (results.topThreats['Port Scanning'] > 0) {
                    recommendations.push('Consider implementing additional port security measures.');
                }
                break;
            case 'dns':
                if (results.topThreats['Phishing'] > 0) {
                    recommendations.push('Implement DNS-based email authentication (SPF, DKIM, DMARC).');
                }
                break;
            case 'user':
                if (results.topThreats['Brute Force Attack'] > 0) {
                    recommendations.push('Implement multi-factor authentication and account lockout policies.');
                }
                break;
        }

        return recommendations;
    }
}

class LogAnalysis {
    constructor() {
        this.classifier = new LogClassifier();
        this.mlEndpoint = 'http://localhost:5000';
    }

    async analyzeLogFile(file, logType) {
        const logs = await this.parseLogFile(file);
        const basicResults = await this.classifier.analyzeLogs(logs, logType);
        
        // Add ML-based analysis
        const mlResults = await this.performMLAnalysis(logs);
        
        return {
            ...basicResults,
            mlAnalysis: mlResults
        };
    }

    async parseLogFile(file) {
        const text = await file.text();
        const lines = text.split('\n').filter(line => line.trim());
        
        return lines.map(line => {
            // Basic log parsing logic - adjust based on your log format
            const [timestamp, ...messageParts] = line.split(' ');
            return {
                timestamp: new Date(timestamp),
                message: messageParts.join(' ')
            };
        });
    }

    async performMLAnalysis(logs) {
        const results = {
            maliciousCount: 0,
            detections: []
        };

        for (const log of logs) {
            try {
                const response = await fetch(`${this.mlEndpoint}/predict`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ log: log.message })
                });

                const prediction = await response.json();
                
                if (prediction.status === 'success') {
                    if (prediction.prediction.is_malicious) {
                        results.maliciousCount++;
                        results.detections.push({
                            log: log.message,
                            confidence: prediction.prediction.confidence,
                            timestamp: log.timestamp
                        });
                    }
                }
            } catch (error) {
                console.error('ML prediction failed:', error);
            }
        }

        return results;
    }
}

class LogAnalyzer {
    constructor() {
        this.subscription = 'basic';
        this.allowedTypes = {
            basic: ['firewall', 'dns', 'user'],
            premium: ['firewall', 'dns', 'user', 'network', 'email', 'application']
        };
        this.logAnalysis = new LogAnalysis();
        this.initializeEventListeners();
        this.chart = null;
        this.initializeChart();
    }

    initializeEventListeners() {
        document.querySelectorAll('.log-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleLogTypeSelection(e));
        });

        document.getElementById('uploadBtn').addEventListener('click', () => this.handleLogUpload());
    }

    initializeChart() {
        const ctx = document.getElementById('logChart').getContext('2d');
        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Log Events',
                    data: [],
                    borderColor: '#ff6b01',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }

    handleLogTypeSelection(e) {
        const logType = e.target.dataset.type;
        if (this.subscription === 'basic' && !this.allowedTypes.basic.includes(logType)) {
            alert('This log type is only available in Premium subscription');
            return;
        }
        
        // Update UI to show selected log type
        document.querySelectorAll('.log-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        e.target.classList.add('active');
        
        // Update chart with mock data for the selected log type
        this.updateChartData(logType);
    }

    async handleLogUpload() {
        const fileInput = document.getElementById('logFile');
        const file = fileInput.files[0];
        
        if (!file) {
            alert('Please select a file to upload');
            return;
        }

        // Simulate log processing
        const logType = this.detectLogType(file.name);
        if (this.subscription === 'basic' && !this.allowedTypes.basic.includes(logType)) {
            alert('Your subscription does not allow uploading this type of log');
            return;
        }

        // Simulate processing
        await this.processLogs(file);
    }

    detectLogType(filename) {
        // Simple detection based on filename
        if (filename.includes('firewall')) return 'firewall';
        if (filename.includes('dns')) return 'dns';
        if (filename.includes('user')) return 'user';
        if (filename.includes('network')) return 'network';
        if (filename.includes('email')) return 'email';
        if (filename.includes('application')) return 'application';
        return 'unknown';
    }

    async processLogs(file) {
        const logType = this.detectLogType(file.name);
        const analysisResults = await this.logAnalysis.analyzeLogFile(file, logType);
        
        // Update UI with basic results
        document.getElementById('totalLogs').textContent = analysisResults.totalLogs;
        document.getElementById('maliciousEvents').textContent = analysisResults.maliciousCount;
        
        // Update ML-specific results
        if (analysisResults.mlAnalysis) {
            const avgConfidence = analysisResults.mlAnalysis.detections.reduce(
                (sum, det) => sum + det.confidence, 0
            ) / (analysisResults.mlAnalysis.detections.length || 1);
            
            document.getElementById('mlConfidence').textContent = 
                `${(avgConfidence * 100).toFixed(1)}%`;
        }
        
        // Update alert level based on severity distribution
        const alertLevel = this.calculateAlertLevel(analysisResults.severityDistribution);
        document.getElementById('alertLevel').textContent = alertLevel;
        
        // Update chart with time-based analysis
        this.updateChartWithAnalysis(analysisResults.timeBasedAnalysis);
        
        // Update table with top threats
        this.updateTableWithThreats(analysisResults.topThreats);
    }

    calculateAlertLevel(severityDistribution) {
        if (severityDistribution.high > 0) return 'High';
        if (severityDistribution.medium > 0) return 'Medium';
        return 'Low';
    }

    updateChartWithAnalysis(timeData) {
        const labels = Object.keys(timeData).sort((a, b) => a - b);
        const data = labels.map(hour => timeData[hour]);
        
        this.chart.data.labels = labels.map(hour => `${hour}:00`);
        this.chart.data.datasets[0].data = data;
        this.chart.update();
    }

    updateTableWithThreats(threats) {
        const tbody = document.querySelector('#logsTable tbody');
        tbody.innerHTML = '';
        
        Object.entries(threats)
            .sort(([,a], [,b]) => b - a)
            .forEach(([threat, count]) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date().toISOString()}</td>
                    <td>${threat}</td>
                    <td>Detected ${count} times</td>
                    <td>Malicious</td>
                `;
                tbody.appendChild(row);
            });
    }

    updateChartData(logType) {
        // Generate mock data based on log type
        const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
        const data = Array.from({length: 24}, () => Math.floor(Math.random() * 100));
        
        this.chart.data.labels = labels;
        this.chart.data.datasets[0].data = data;
        this.chart.data.datasets[0].label = `${logType.toUpperCase()} Events`;
        this.chart.update();
    }

    updateLogTable() {
        const tbody = document.querySelector('#logsTable tbody');
        tbody.innerHTML = ''; // Clear existing rows
        
        // Add mock log entries
        for (let i = 0; i < 10; i++) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date().toISOString()}</td>
                <td>Firewall</td>
                <td>Connection attempt blocked</td>
                <td>${Math.random() > 0.5 ? 'Malicious' : 'Normal'}</td>
            `;
            tbody.appendChild(row);
        }
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    const logAnalyzer = new LogAnalyzer();
}); 