// Package detect provides anomaly detection capabilities.
package detect

import (
	"regexp"
	"time"
)

// Detector detects runtime anomalies.
type Detector struct {
	patterns []*Pattern
}

// Pattern defines a detection pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Category    string
	Severity    string
	Description string
}

// SystemEvent represents a system event for analysis.
type SystemEvent struct {
	Type        string
	Timestamp   time.Time
	Data        map[string]interface{}
	ProcessName string
	PID         int
}

// AnomalyResult contains detection results.
type AnomalyResult struct {
	Pattern     string
	Severity    string
	Confidence  float64
	Description string
	Recommendation string
}

// NewDetector creates a new anomaly detector.
func NewDetector() *Detector {
	return &Detector{
		patterns: []*Pattern{
			{
				Name:        "Excessive File Access",
				Regex:       regexp.MustCompile(`(?i)\b(open|read|write|close)\s*\(\s*["']`),
				Category:    "file",
				Severity:    "MEDIUM",
				Description: "High frequency file access detected",
			},
			{
				Name:        "Network Connection Spike",
				Regex:       regexp.MustCompile(`(?i)\b(connect|socket|listen|accept)\s*\( `),
				Category:    "network",
				Severity:    "HIGH",
				Description: "Abnormal network connection activity",
			},
			{
				Name:        "Process Fork Bomb",
				Regex:       regexp.MustCompile(`(?i)\b(fork|spawn|exec)\s*\( `),
				Category:    "process",
				Severity:    "CRITICAL",
				Description: "Excessive process creation detected",
			},
			{
				Name:        "System Call Spike",
				Regex:       regexp.MustCompile(`(?i)\b(syscall)\b`),
				Category:    "syscall",
				Severity:    "MEDIUM",
				Description: "High system call frequency",
			},
		},
	}
}

// Detect detects anomalies in system events.
func (d *Detector) Detect(events []SystemEvent) []AnomalyResult {
	var results []AnomalyResult

	// Count events by category
	categoryCounts := make(map[string]int)
	for _, event := range events {
		categoryCounts[event.Type]++
	}

	// Check for anomalies
	for _, pattern := range d.patterns {
		count := categoryCounts[pattern.Category]
		if count > 100 { // Threshold for detection
			results = append(results, AnomalyResult{
				Pattern:     pattern.Name,
				Severity:    pattern.Severity,
				Confidence:  float64(count) / 200.0,
				Description: pattern.Description,
				Recommendation: "Review and investigate this activity",
			})
		}
	}

	return results
}

// AnalyzeBehavior analyzes behavioral patterns.
func AnalyzeBehavior(events []SystemEvent) map[string]interface{} {
	analysis := map[string]interface{}{
		"total_events": len(events),
		"by_category":  make(map[string]int),
		"by_process":   make(map[string]int),
		"time_range":   struct{ Start, End string }{},
	}

	var timestamps []time.Time

	for _, event := range events {
		analysis["by_category"].(map[string]int)[event.Type]++
		analysis["by_process"].(map[string]int][event.ProcessName]++

		timestamps = append(timestamps, event.Timestamp)
	}

	if len(timestamps) > 0 {
		minTime := timestamps[0]
		maxTime := timestamps[0]
		for _, t := range timestamps {
			if t.Before(minTime) {
				minTime = t
			}
			if t.After(maxTime) {
				maxTime = t
			}
		}
		analysis["time_range"] = struct{ Start, End string }{
			Start: minTime.Format(time.RFC3339),
			End:   maxTime.Format(time.RFC3339),
		}
	}

	return analysis
}

// CalculateBehaviorScore calculates behavior score.
func CalculateBehaviorScore(events []SystemEvent, baseline map[string]int) float64 {
	if len(baseline) == 0 {
		return 100.0
	}

	totalEvents := float64(len(events))
	totalBaseline := float64(0)
	for _, count := range baseline {
		totalBaseline += float64(count)
	}

	if totalBaseline == 0 {
		return 100.0
	}

	ratio := totalEvents / totalBaseline
	score := 100.0 - (ratio-1)*50 // Penalize deviations

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// DetectSystemCallAnomaly detects syscall anomalies.
func DetectSystemCallAnomaly(syscalls []string, baseline map[string]int) []string {
	var anomalies []string

	for _, syscall := range syscalls {
		count := 0
		for _, s := range syscalls {
			if s == syscall {
				count++
			}
		}

		expected, exists := baseline[syscall]
		if exists && count > expected*3 {
			anomalies = append(anomalies, syscall)
		}
	}

	return anomalies
}

// DetectFileAccessAnomaly detects file access anomalies.
func DetectFileAccessAnomaly(files []string, baseline map[string]int) []string {
	var anomalies []string
	seen := make(map[string]bool)

	for _, file := range files {
		if seen[file] {
			continue
		}
		seen[file] = true

		count := 0
		for _, f := range files {
			if f == file {
				count++
			}
		}

		expected, exists := baseline[file]
		if exists && count > expected*5 {
			anomalies = append(anomalies, file)
		}
	}

	return anomalies
}

// DetectNetworkAnomaly detects network anomalies.
func DetectNetworkAnomaly(connections []string, baseline map[string]int) []string {
	var anomalies []string
	seen := make(map[string]bool)

	for _, conn := range connections {
		if seen[conn] {
			continue
		}
		seen[conn] = true

		count := 0
		for _, c := range connections {
			if c == conn {
				count++
			}
		}

		expected, exists := baseline[conn]
		if exists && count > expected*3 {
			anomalies = append(anomalies, conn)
		}
	}

	return anomalies
}

// GenerateReport generates anomaly report.
func GenerateReport(anomalies []AnomalyResult) string {
	var report string

	report += "=== Behavior Anomaly Report ===\n\n"
	report += "Total anomalies detected: " + string(rune(len(anomalies)+48)) + "\n\n"

	for i, anomaly := range anomalies {
		report += "[" + string(rune(i+49)) + "] " + anomaly.Pattern + "\n"
		report += "    Severity: " + anomaly.Severity + "\n"
		report += "    Confidence: " + string(rune(int(anomaly.Confidence*100)+48)) + "%\n"
		report += "    Description: " + anomaly.Description + "\n"
		report += "    Recommendation: " + anomaly.Recommendation + "\n\n"
	}

	return report
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}