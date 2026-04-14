package connections

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ExecuteAPI makes an HTTP request to an API endpoint.
// method and path come from passthrough args.
// body is optional (for POST/PUT).
func ExecuteAPI(baseURL, authType, authHeader, authValue string, extraHeaders map[string]string, insecure bool, method, path, body string) Result {
	url := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return Result{Error: fmt.Errorf("failed to create request: %w", err)}
	}

	// Set auth
	switch authType {
	case "key":
		if authHeader == "" {
			authHeader = "X-API-KEY"
		}
		req.Header.Set(authHeader, authValue)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+authValue)
	case "basic":
		// authValue should be "user:pass"
		parts := strings.SplitN(authValue, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}

	// Set extra headers
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	if req.Header.Get("Content-Type") == "" && body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{Error: fmt.Errorf("request failed: %w", err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{Error: fmt.Errorf("failed to read response: %w", err)}
	}

	return Result{
		Output:   string(respBody),
		ExitCode: resp.StatusCode,
	}
}

// TestAPI tests connectivity to an API endpoint.
// Uses a HEAD request with no redirect following to avoid redirect loops.
func TestAPI(baseURL, authType, authHeader, authValue string, insecure bool) error {
	url := strings.TrimRight(baseURL, "/")

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	switch authType {
	case "key":
		header := authHeader
		if header == "" {
			header = "X-API-KEY"
		}
		req.Header.Set(header, authValue)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+authValue)
	case "basic":
		parts := strings.SplitN(authValue, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("API connection failed: %v", err)
	}
	resp.Body.Close()

	// Any response (even redirects) means the server is reachable
	if resp.StatusCode >= 500 {
		return fmt.Errorf("API returned server error: %d", resp.StatusCode)
	}
	return nil
}
