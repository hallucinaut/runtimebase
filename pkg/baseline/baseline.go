// Package baseline provides runtime behavior baseline analysis.
package baseline

import (
	"regexp"
	"time"
)

// BehaviorPattern represents a detected behavioral pattern.
type BehaviorPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Category    string // syscall, file, network, process
	NormalCount float64
	Threshold   float64
}

// Baseline represents learned runtime behavior.
type Baseline struct {
	Name           string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Patterns       []BehaviorPattern
	Stats          map[string]Stat
	AnomalyThreshold float64
}

// Stat represents statistical data for a pattern.
type Stat struct {
	Mean        float64
	StdDev      float64
	Min         float64
	Max         float64
	SampleCount int
}

// Anomaly represents a detected behavioral anomaly.
type Anomaly struct {
	Type         string
	Description  string
	Severity     string
	Evidence     string
	Confidence   float64
	Timestamp    time.Time
	RiskLevel    string
}

// Learner learns runtime behavior patterns.
type Learner struct {
	baselines map[string]*Baseline
}

// NewLearner creates a new behavior learner.
func NewLearner() *Learner {
	return &Learner{
		baselines: make(map[string]*Baseline),
	}
}

// CreateBaseline creates a new behavior baseline.
func (l *Learner) CreateBaseline(name string) *Baseline {
	baseline := &Baseline{
		Name:           name,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Patterns:       make([]BehaviorPattern, 0),
		Stats:          make(map[string]Stat),
		AnomalyThreshold: 3.0, // 3 standard deviations
	}
	l.baselines[name] = baseline
	return baseline
}

// GetBaseline retrieves a baseline by name.
func (l *Learner) GetBaseline(name string) *Baseline {
	return l.baselines[name]
}

// RecordObservation records a behavioral observation.
func (b *Baseline) RecordObservation(category, pattern string, count int) {
	key := category + ":" + pattern
	if _, exists := b.Stats[key]; !exists {
		b.Stats[key] = Stat{}
	}
	stat := b.Stats[key]
	stat.SampleCount++
	b.Stats[key] = stat
}

// LearnFromFile learns from a log file.
func (l *Learner) LearnFromFile(filepath string) error {
	// Placeholder - would read and analyze log file
	// In production: parse logs, extract patterns, update baselines
	return nil
}

// DetectAnomaly detects anomalies against baseline.
func (l *Learner) DetectAnomaly(name, category, pattern string, count int) []Anomaly {
	var anomalies []Anomaly

	baseline := l.GetBaseline(name)
	if baseline == nil {
		return anomalies
	}

	key := category + ":" + pattern
	stat, exists := baseline.Stats[key]

	if exists {
		// Calculate z-score
		zScore := (float64(count) - stat.Mean) / stat.StdDev

		if zScore > baseline.AnomalyThreshold || zScore < -baseline.AnomalyThreshold {
			anomalies = append(anomalies, Anomaly{
				Type:         "Behavioral Anomaly",
				Description:  "Observed behavior deviates from baseline",
				Severity:     getSeverity(zScore),
				Evidence:     pattern,
				Confidence:   calculateConfidence(zScore),
				Timestamp:    time.Now(),
				RiskLevel:    getRiskLevel(zScore),
			})
		}
	}

	return anomalies
}

// GetSeverity returns severity based on z-score.
func getSeverity(zScore float64) string {
	if zScore > 5 {
		return "CRITICAL"
	} else if zScore > 3 {
		return "HIGH"
	} else if zScore > 2 {
		return "MEDIUM"
	}
	return "LOW"
}

// CalculateConfidence calculates anomaly confidence.
func calculateConfidence(zScore float64) float64 {
	// Convert z-score to confidence (0-1)
	confidence := 1 - (1 / (1 + zScore*zScore/2))
	if confidence > 1 {
		confidence = 1
	}
	return confidence
}

// GetRiskLevel returns risk level based on z-score.
func getRiskLevel(zScore float64) string {
	if zScore > 5 {
		return "CRITICAL"
	} else if zScore > 3 {
		return "HIGH"
	} else if zScore > 2 {
		return "MEDIUM"
	}
	return "LOW"
}

// UpdateBaseline updates baseline statistics.
func (b *Baseline) UpdateBaseline(category, pattern string, count float64) {
	key := category + ":" + pattern
	if _, exists := b.Stats[key]; !exists {
		b.Stats[key] = Stat{
			Mean:  count,
			StdDev: 0,
			Min:   count,
			Max:   count,
		}
		return
	}

	stat := b.Stats[key]
	stat.Mean = (stat.Mean*float64(stat.SampleCount) + count) / float64(stat.SampleCount+1)
	stat.Max = max(stat.Max, count)
	stat.Min = min(stat.Min, count)
	b.Stats[key] = stat
}

// GetAnomalyReport generates anomaly report.
func GetAnomalyReport(anomalies []Anomaly) map[string]interface{} {
	report := map[string]interface{}{
		"total_anomalies": len(anomalies),
		"by_severity":     make(map[string]int),
		"by_risk":         make(map[string]int),
	}

	for _, anomaly := range anomalies {
		report["by_severity"].(map[string]int)[anomaly.Severity]++
		report["by_risk"].(map[string]int)[anomaly.RiskLevel]++
	}

	return report
}

// IsNormal checks if behavior is within normal range.
func IsNormal(count, mean, stddev, threshold float64) bool {
	if stddev == 0 {
		return count == mean
	}
	zScore := (count - mean) / stddev
	return zScore <= threshold && zScore >= -threshold
}

// CalculateZScore calculates z-score for anomaly detection.
func CalculateZScore(value, mean, stddev float64) float64 {
	if stddev == 0 {
		return 0
	}
	return (value - mean) / stddev
}