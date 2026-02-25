# runtimebase - Runtime Behavior Baseline

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Learn normal runtime behavior and detect deviations for security monitoring.**

Establish behavioral baselines for applications and detect anomalies that may indicate security incidents.

## 🚀 Features

- **Behavior Learning**: Learn normal runtime patterns from system activity
- **Anomaly Detection**: Detect deviations from established baselines
- **Multi-Category Analysis**: Track syscall, file, network, and process behaviors
- **Statistical Analysis**: Use z-scores and standard deviations for detection
- **Risk Scoring**: Calculate behavioral risk scores (0-100%)
- **Real-time Monitoring**: Continuous behavior analysis and alerting

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/runtimebase.git
cd runtimebase
go build -o runtimebase ./cmd/runtimebase
sudo mv runtimebase /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/runtimebase/cmd/runtimebase@latest
```

## 🎯 Usage

### Learn Baseline

```bash
# Create and learn new baseline
runtimebase learn myapp

# Collect behavior data programmatically
baseline.RecordObservation("syscall", "open", 100)
baseline.RecordObservation("file", "read", 500)
```

### Detect Anomalies

```bash
# Detect anomalies against baseline
runtimebase detect myapp

# Check current behavior
runtimebase check myapp
```

### Analyze Logs

```bash
# Analyze log files for patterns
runtimebase analyze /var/log/myapp.log
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/runtimebase/pkg/baseline"
    "github.com/hallucinaut/runtimebase/pkg/detect"
)

func main() {
    // Create learner
    learner := baseline.NewLearner()
    b := learner.CreateBaseline("myapp")

    // Learn behavior
    b.RecordObservation("syscall", "open", 100)
    b.RecordObservation("file", "read", 500)

    // Detect anomalies
    anomalies := learner.DetectAnomaly("myapp", "syscall", "open", 500)

    fmt.Printf("Found %d anomalies\n", len(anomalies))

    // Calculate behavior score
    score := detect.CalculateBehaviorScore(events, baseline)
    fmt.Printf("Behavior Score: %.0f%%\n", score)
}
```

## 🔍 Detection Categories

| Category | Examples | Use Case |
|----------|----------|----------|
| syscall | open, read, write, close | System call frequency analysis |
| file | file access patterns | File access behavior monitoring |
| network | connections, sockets | Network activity tracking |
| process | fork, exec, spawn | Process creation monitoring |

## 📊 Anomaly Detection

### Z-Score Based Detection

Z-scores measure how many standard deviations a value is from the mean:

- **Z > 5**: CRITICAL anomaly (99.999% confidence)
- **Z > 3**: HIGH anomaly (99.7% confidence)
- **Z > 2**: MEDIUM anomaly (95% confidence)
- **Z ≤ 2**: Within normal range

### Behavior Score

| Score | Status | Action |
|-------|--------|--------|
| 90-100 | Excellent | Normal operation |
| 70-89 | Good | Minor deviations |
| 50-69 | Fair | Investigate |
| <50 | Poor | Immediate action |

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/baseline -run TestDetectAnomaly
```

## 📋 Example Output

```
Detecting anomalies for: myapp

Found 2 anomalies:

[1] HIGH - Behavioral Anomaly
    Evidence: syscall:open
    Confidence: 85%
    Risk Level: HIGH

[2] MEDIUM - Behavioral Anomaly
    Evidence: file:write
    Confidence: 72%
    Risk Level: MEDIUM

Behavior Score: 78%
Status: Good - Minor deviations
```

## 🔒 Security Use Cases

- **Malware Detection**: Detect abnormal behavior patterns
- **Insider Threats**: Identify unusual user activity
- **Data Exfiltration**: Detect abnormal file/network access
- **Privilege Escalation**: Monitor for suspicious process creation
- **Ransomware Detection**: Identify rapid file access patterns

## 🛡️ Best Practices

1. **Establish baselines during normal operation**
2. **Collect sufficient data for statistical significance**
3. **Use multiple detection categories for accuracy**
4. **Set appropriate thresholds based on your environment**
5. **Regularly update baselines as behavior changes**

## 🏗️ Architecture

```
runtimebase/
├── cmd/
│   └── runtimebase/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── baseline/
│   │   ├── baseline.go      # Baseline management
│   │   └── baseline_test.go # Unit tests
│   └── detect/
│       ├── detect.go        # Anomaly detection
│       └── detect_test.go   # Unit tests
└── README.md
```

## 📄 License

MIT License

## 🙏 Acknowledgments

- Anomaly detection research community
- Runtime security monitoring best practices
- Statistical analysis methodologies

---

**Built with GPU by [hallucinaut](https://github.com/hallucinaut)**