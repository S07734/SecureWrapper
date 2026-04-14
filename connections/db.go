package connections

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/microsoft/go-mssqldb"
)

// DBConfig captures everything needed to open a database connection. Kept
// driver-agnostic at the call site so the caller passes the same struct for
// postgres/mysql/mssql and the DSN builder picks fields accordingly.
type DBConfig struct {
	Driver   string // "postgres", "mysql", "sqlserver"
	Host     string
	Port     int
	Username string
	Password string
	Database string
	SSLMode  string // postgres: disable/require/verify-ca/verify-full; mysql: false/true/skip-verify/preferred; mssql: disable/false/true/strict
}

const dbOpenTimeout = 10 * time.Second

// ExecuteDB opens a connection using cfg, pings to verify reachability, then
// runs the query. If the query returns rows, they are rendered as TSV with a
// header line. If the query is a non-query (INSERT/UPDATE/DELETE), "N rows
// affected" is returned. An empty query is a connectivity test.
func ExecuteDB(cfg DBConfig, query string) Result {
	dsn, err := BuildDSN(cfg)
	if err != nil {
		return Result{Error: fmt.Errorf("build DSN: %w", err), ExitCode: 1}
	}

	db, err := sql.Open(cfg.Driver, dsn)
	if err != nil {
		return Result{Error: fmt.Errorf("open: %w", err), ExitCode: 1}
	}
	defer db.Close()

	db.SetConnMaxLifetime(dbOpenTimeout)

	if err := pingWithTimeout(db, dbOpenTimeout); err != nil {
		return Result{Error: fmt.Errorf("connect: %w", err), ExitCode: 1}
	}

	if strings.TrimSpace(query) == "" {
		return Result{Output: "OK"}
	}

	// Try as a rows query first; if driver reports no columns it was an exec.
	rows, err := db.Query(query)
	if err != nil {
		return Result{Error: fmt.Errorf("query: %w", err), ExitCode: 1}
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return Result{Error: fmt.Errorf("columns: %w", err), ExitCode: 1}
	}

	if len(cols) == 0 {
		// Some drivers return 0 columns for exec-style statements; fall back
		// to a separate Exec call to get RowsAffected.
		rows.Close()
		res, err := db.Exec(query)
		if err != nil {
			return Result{Error: fmt.Errorf("exec: %w", err), ExitCode: 1}
		}
		affected, _ := res.RowsAffected()
		return Result{Output: fmt.Sprintf("%d rows affected", affected)}
	}

	out, err := formatRowsTSV(rows, cols)
	if err != nil {
		return Result{Error: err, ExitCode: 1}
	}
	return Result{Output: out}
}

// pingWithTimeout wraps db.Ping in a timeout. database/sql doesn't enforce a
// connect timeout on Ping itself; wrapping it guards against hung drivers.
func pingWithTimeout(db *sql.DB, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- db.Ping() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("ping timed out after %s", timeout)
	}
}

// formatRowsTSV renders rows as tab-separated values with a header line.
// NULL scans to empty string; tabs and newlines in values are replaced with
// spaces to keep the TSV shape parseable by simple line-splitters.
func formatRowsTSV(rows *sql.Rows, cols []string) (string, error) {
	var b strings.Builder
	b.WriteString(strings.Join(cols, "\t"))
	b.WriteString("\n")

	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}

	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return "", fmt.Errorf("scan: %w", err)
		}
		parts := make([]string, len(cols))
		for i, v := range vals {
			parts[i] = sanitizeCell(formatValue(v))
		}
		b.WriteString(strings.Join(parts, "\t"))
		b.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate: %w", err)
	}
	return b.String(), nil
}

func formatValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case []byte:
		return string(val)
	case time.Time:
		return val.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// sanitizeCell flattens tabs and newlines so TSV parsing by line+tab stays
// deterministic. Multi-line text loses formatting but stays in the same cell.
func sanitizeCell(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// BuildDSN assembles a driver-specific connection string. Exposed for tests.
func BuildDSN(cfg DBConfig) (string, error) {
	if cfg.Host == "" {
		return "", fmt.Errorf("host required")
	}
	if cfg.Port == 0 {
		cfg.Port = defaultPortFor(cfg.Driver)
	}

	switch cfg.Driver {
	case "postgres":
		u := url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(cfg.Username, cfg.Password),
			Host:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Path:   cfg.Database,
		}
		q := url.Values{}
		if cfg.SSLMode != "" {
			q.Set("sslmode", cfg.SSLMode)
		} else {
			q.Set("sslmode", "require")
		}
		q.Set("connect_timeout", fmt.Sprintf("%d", int(dbOpenTimeout.Seconds())))
		u.RawQuery = q.Encode()
		return u.String(), nil

	case "mysql":
		// mysql driver DSN: user:pass@tcp(host:port)/dbname?params
		params := url.Values{}
		params.Set("parseTime", "true")
		params.Set("timeout", dbOpenTimeout.String())
		if cfg.SSLMode != "" {
			params.Set("tls", cfg.SSLMode)
		}
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?%s",
			cfg.Username, cfg.Password, cfg.Host, cfg.Port,
			cfg.Database, params.Encode()), nil

	case "sqlserver":
		u := url.URL{
			Scheme: "sqlserver",
			User:   url.UserPassword(cfg.Username, cfg.Password),
			Host:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		}
		q := url.Values{}
		if cfg.Database != "" {
			q.Set("database", cfg.Database)
		}
		if cfg.SSLMode != "" {
			q.Set("encrypt", cfg.SSLMode)
		}
		q.Set("connection timeout", fmt.Sprintf("%d", int(dbOpenTimeout.Seconds())))
		u.RawQuery = q.Encode()
		return u.String(), nil

	default:
		return "", fmt.Errorf("unsupported driver %q", cfg.Driver)
	}
}

func defaultPortFor(driver string) int {
	switch driver {
	case "postgres":
		return 5432
	case "mysql":
		return 3306
	case "sqlserver":
		return 1433
	}
	return 0
}
