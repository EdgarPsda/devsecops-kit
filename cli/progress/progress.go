package progress

import (
	"fmt"
	"sync"
	"time"
)

// Scanner represents a scanner being tracked
type Scanner struct {
	Name       string
	Status     string // "pending", "running", "completed", "error"
	Progress   int    // 0-100
	Error      error
	StartTime  time.Time
	EndTime    time.Time
}

// Tracker manages progress of multiple scanners
type Tracker struct {
	mu       sync.RWMutex
	scanners map[string]*Scanner
	done     chan bool
	ticker   *time.Ticker
}

// NewTracker creates a new progress tracker
func NewTracker() *Tracker {
	return &Tracker{
		scanners: make(map[string]*Scanner),
		done:     make(chan bool),
		ticker:   time.NewTicker(100 * time.Millisecond),
	}
}

// AddScanner adds a scanner to track
func (t *Tracker) AddScanner(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.scanners[name] = &Scanner{
		Name:     name,
		Status:   "pending",
		Progress: 0,
	}
}

// StartScanner marks a scanner as running
func (t *Tracker) StartScanner(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if scanner, ok := t.scanners[name]; ok {
		scanner.Status = "running"
		scanner.Progress = 0
		scanner.StartTime = time.Now()
	}
}

// UpdateProgress updates the progress of a scanner
func (t *Tracker) UpdateProgress(name string, progress int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if scanner, ok := t.scanners[name]; ok {
		if progress > 100 {
			progress = 100
		}
		scanner.Progress = progress
	}
}

// CompleteScanner marks a scanner as completed
func (t *Tracker) CompleteScanner(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if scanner, ok := t.scanners[name]; ok {
		scanner.Status = "completed"
		scanner.Progress = 100
		scanner.EndTime = time.Now()
	}
}

// ErrorScanner marks a scanner with an error
func (t *Tracker) ErrorScanner(name string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if scanner, ok := t.scanners[name]; ok {
		scanner.Status = "error"
		scanner.Error = err
		scanner.EndTime = time.Now()
	}
}

// Start begins displaying progress
func (t *Tracker) Start() {
	go t.displayProgress()
}

// Stop stops the progress display
func (t *Tracker) Stop() {
	t.ticker.Stop()
	t.done <- true
	t.displayFinal()
}

// displayProgress shows real-time progress
func (t *Tracker) displayProgress() {
	for {
		select {
		case <-t.done:
			return
		case <-t.ticker.C:
			t.mu.RLock()
			scanners := t.scanners
			t.mu.RUnlock()

			// Clear screen and display progress
			fmt.Print("\033[H\033[2J") // Clear screen
			fmt.Println("🔍 Running security scans...\n")

			for _, scanner := range scanners {
				bar := t.progressBar(scanner.Progress)
				status := t.statusIcon(scanner.Status)

				duration := ""
				if scanner.Status == "completed" || scanner.Status == "error" {
					duration = fmt.Sprintf(" (%.1fs)", scanner.EndTime.Sub(scanner.StartTime).Seconds())
				}

				fmt.Printf("%s %-15s %s %d%%%s\n", status, scanner.Name, bar, scanner.Progress, duration)

				if scanner.Status == "error" && scanner.Error != nil {
					fmt.Printf("   ❌ Error: %v\n", scanner.Error)
				}
			}

			fmt.Println()
		}
	}
}

// displayFinal displays the final state without progress bars
func (t *Tracker) displayFinal() {
	t.mu.RLock()
	defer t.mu.RUnlock()

	fmt.Print("\033[H\033[2J") // Clear screen
	fmt.Println("🔍 Running security scans...\n")

	for _, scanner := range t.scanners {
		status := ""
		switch scanner.Status {
		case "completed":
			status = "✅"
		case "error":
			status = "❌"
		case "pending":
			status = "⏭️"
		default:
			status = "⏳"
		}

		duration := ""
		if scanner.Status == "completed" || scanner.Status == "error" {
			duration = fmt.Sprintf(" (%.1fs)", scanner.EndTime.Sub(scanner.StartTime).Seconds())
		}

		fmt.Printf("%s %-15s [██████████] 100%%%s\n", status, scanner.Name, duration)
	}

	fmt.Println()
}

// progressBar returns a visual progress bar
func (t *Tracker) progressBar(progress int) string {
	filled := (progress / 10)
	empty := 10 - filled

	bar := "["
	for i := 0; i < filled; i++ {
		bar += "█"
	}
	for i := 0; i < empty; i++ {
		bar += "░"
	}
	bar += "]"

	return bar
}

// statusIcon returns the status emoji
func (t *Tracker) statusIcon(status string) string {
	switch status {
	case "completed":
		return "✅"
	case "error":
		return "❌"
	case "running":
		return "⏳"
	case "pending":
		return "⏭️"
	default:
		return "❓"
	}
}
