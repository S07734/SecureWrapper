package connections

// Result holds the output from a connection execution.
type Result struct {
	Output   string
	ExitCode int
	Error    error
}
