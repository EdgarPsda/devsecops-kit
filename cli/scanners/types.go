package scanners

// ScanResult represents the output from a single scanner run
type ScanResult struct {
	Tool       string        `json:"tool"`       // "semgrep", "gitleaks", "trivy"
	Status     string        `json:"status"`     // "success", "error", "no_findings"
	Error      error         `json:"-"`
	Findings   []Finding     `json:"findings"`
	Summary    FindingSummary `json:"summary"`
}

// Finding represents a single security finding
type Finding struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Column     int    `json:"column,omitempty"`
	Severity   string `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW", or rule ID
	Message    string `json:"message"`
	RuleID     string `json:"rule_id,omitempty"`
	Tool       string `json:"tool"`
	RemoteURL  string `json:"remote_url,omitempty"` // Link to rule documentation
}

// FindingSummary contains aggregated counts
type FindingSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ScanOptions controls how scanners are executed
type ScanOptions struct {
	EnableSemgrep    bool
	EnableGitleaks   bool
	EnableTrivy      bool
	EnableTrivyImage bool
	DockerImages     []string
	ExcludePaths     []string
	FailOnThresholds map[string]int
	Verbose          bool
}

// ScanReport aggregates all scan results
type ScanReport struct {
	Timestamp   string                        `json:"timestamp"`
	Status      string                        `json:"status"` // "PASS" or "FAIL"
	BlockingCount int                         `json:"blocking_count"`
	Results     map[string]*ScanResult        `json:"results"` // key: tool name
	AllFindings []Finding                     `json:"all_findings"`
}
