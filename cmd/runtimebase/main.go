package main

import (
	"fmt"
	"os"
//	"path/filepath"

	"github.com/hallucinaut/runtimebase/pkg/baseline"
//	"github.com/hallucinaut/runtimebase/pkg/detect"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "learn":
		if len(os.Args) < 3 {
			fmt.Println("Error: baseline name required")
			printUsage()
			return
		}
		learnBaseline(os.Args[2])
	case "detect":
		if len(os.Args) < 3 {
			fmt.Println("Error: baseline name required")
			printUsage()
			return
		}
		detectAnomalies(os.Args[2])
	case "analyze":
		if len(os.Args) < 3 {
			fmt.Println("Error: log file required")
			printUsage()
			return
		}
		analyzeLog(os.Args[2])
	case "check":
		if len(os.Args) < 3 {
			fmt.Println("Error: baseline name required")
			printUsage()
			return
		}
		checkBehavior(os.Args[2])
	case "version":
		fmt.Printf("runtimebase version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`runtimebase - Runtime Behavior Baseline

Usage:
  runtimebase <command> [options]

Commands:
  learn <name>    Create and learn new behavior baseline
  detect <name>   Detect anomalies against baseline
  analyze <file>  Analyze log file for behavioral patterns
  check <name>    Check current behavior against baseline
  version         Show version information
  help            Show this help message

Examples:
  runtimebase learn myapp
  runtimebase detect myapp
  runtimebase analyze /var/log/myapp.log
`,)
}

func learnBaseline(name string) {
	learner := baseline.NewLearner()
	baseline := learner.CreateBaseline(name)

	fmt.Printf("Learning baseline: %s\n", name)
	fmt.Printf("Created at: %s\n", baseline.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println()
	fmt.Println("Baseline initialized. Start collecting behavior data...")
	fmt.Println("Use RecordObservation() to learn patterns:")
	fmt.Println("  baseline.RecordObservation(\"syscall\", \"open\", 100)")
	fmt.Println("  baseline.RecordObservation(\"file\", \"read\", 500)")
}

func detectAnomalies(name string) {
	learner := baseline.NewLearner()
	baseline := learner.CreateBaseline(name)

	fmt.Printf("Detecting anomalies for: %s\n", name)
	fmt.Println()

	// Simulate some observations
	baseline.RecordObservation("syscall", "open", 100)
	baseline.RecordObservation("syscall", "read", 500)
	baseline.RecordObservation("file", "write", 200)

	// Detect anomalies
	anomalies := learner.DetectAnomaly(name, "syscall", "open", 500)

	if len(anomalies) > 0 {
		fmt.Printf("Found %d anomalies:\n\n", len(anomalies))
		for i, anomaly := range anomalies {
			fmt.Printf("[%d] %s - %s\n", i+1, anomaly.Severity, anomaly.Type)
			fmt.Printf("    Evidence: %s\n", anomaly.Evidence)
			fmt.Printf("    Confidence: %.0f%%\n", anomaly.Confidence*100)
			fmt.Printf("    Risk Level: %s\n\n", anomaly.RiskLevel)
		}
	} else {
		fmt.Println("No anomalies detected - behavior within normal range")
	}
}

func analyzeLog(filepath string) {
	fmt.Printf("Analyzing log file: %s\n", filepath)
	fmt.Println()

	// In production: read and parse log file
	// For demo: show analysis template
	fmt.Println("Log analysis template:")
	fmt.Println("1. Parse log entries")
	fmt.Println("2. Extract behavioral patterns")
	fmt.Println("3. Calculate statistics")
	fmt.Println("4. Generate baseline")
	fmt.Println()
	fmt.Println("Supported log formats:")
	fmt.Println("  - Syscall traces")
	fmt.Println("  - File access logs")
	fmt.Println("  - Network connection logs")
	fmt.Println("  - Process activity logs")
}

func checkBehavior(name string) {
//	learner := baseline.NewLearner()
//	baseline := learner.CreateBaseline(name)

	fmt.Printf("Checking behavior against baseline: %s\n", name)
	fmt.Println()

	// Example check
//	isNormal := baseline.IsNormal(100, 100, 10, 3.0)
//	if isNormal {
//		fmt.Println("✓ Behavior is within normal parameters")
//	} else {
//		fmt.Println("⚠ Behavior deviates from baseline")
//	}
//
//	// Calculate behavior score
//	score := detect.CalculateBehaviorScore([]interface{}{}, map[string]int{"syscall": 100, "file": 500})
//	fmt.Printf("\nBehavior Score: %.0f%%\n", score)
//
//	if score >= 90 {
//		fmt.Println("Status: Excellent - No anomalies detected")
//	} else if score >= 70 {
//		fmt.Println("Status: Good - Minor deviations")
//	} else if score >= 50 {
//		fmt.Println("Status: Fair - Investigate further")
//	} else {
		fmt.Println("Status: Poor - Immediate action required")
//	}
}

func getType(info os.FileInfo) string {
	if info.IsDir() {
		return "directory"
	}
	return "file"
}