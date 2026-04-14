package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"
)

// Trusted time sources. HTTPS is primary — authenticated by TLS, works through
// firewalls. NTP is a fallback for environments where TLS is intercepted or all
// HTTPS sources are unreachable.
var httpsTimeSources = []string{
	"https://www.google.com",
	"https://www.cloudflare.com",
	"https://www.apple.com",
}

var ntpTimeSources = []string{
	"time.cloudflare.com:123",
	"time.google.com:123",
	"pool.ntp.org:123",
}

const (
	// trustedTimeWindow — max spread between agreeing sources
	trustedTimeWindow = 60 * time.Second
	// trustedTimeTimeout — per-source network timeout
	trustedTimeTimeout = 5 * time.Second
	// minAgreeingSources — require at least this many sources agreeing
	minAgreeingSources = 2
)

// trustedTimeFn is the overridable entry point for trusted-time lookups.
// Tests replace this with a deterministic stub.
var trustedTimeFn = trustedTimeNetwork

// TrustedTime returns a network-verified current time. Queries HTTPS sources
// first; if fewer than 2 respond, falls back to NTP. Returns an error if no
// consensus can be reached — callers MUST NOT fall back to the local clock
// for security-critical checks.
func TrustedTime() (time.Time, error) {
	return trustedTimeFn()
}

func trustedTimeNetwork() (time.Time, error) {
	httpsResults := fetchHTTPSTimes(httpsTimeSources)
	if t, ok := consensus(httpsResults, trustedTimeWindow, minAgreeingSources); ok {
		return t, nil
	}

	ntpResults := fetchNTPTimes(ntpTimeSources)
	if t, ok := consensus(ntpResults, trustedTimeWindow, minAgreeingSources); ok {
		return t, nil
	}

	combined := append(httpsResults, ntpResults...)
	if t, ok := consensus(combined, trustedTimeWindow, minAgreeingSources); ok {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("could not verify current time — need at least %d agreeing sources (got %d responses). Check network connectivity.", minAgreeingSources, len(combined))
}

// fetchHTTPSTimes issues HEAD requests to each URL in parallel and collects
// the Date response headers. Parse errors and network failures are silently
// dropped — consensus logic handles the quorum.
func fetchHTTPSTimes(urls []string) []time.Time {
	results := make(chan time.Time, len(urls))
	for _, url := range urls {
		go func(u string) {
			results <- fetchHTTPSDate(u)
		}(url)
	}

	var times []time.Time
	for range urls {
		select {
		case t := <-results:
			if !t.IsZero() {
				times = append(times, t)
			}
		case <-time.After(trustedTimeTimeout + time.Second):
			// Per-source timeout already covers this; outer is just a safety net.
			return times
		}
	}
	return times
}

func fetchHTTPSDate(url string) time.Time {
	client := &http.Client{Timeout: trustedTimeTimeout}
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return time.Time{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}
	}
	defer resp.Body.Close()

	dateHeader := resp.Header.Get("Date")
	if dateHeader == "" {
		return time.Time{}
	}
	t, err := parseHTTPDate(dateHeader)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseHTTPDate parses an HTTP Date header per RFC 7231 § 7.1.1.1.
// Accepts the preferred IMF-fixdate form and the obsolete RFC 850 form.
func parseHTTPDate(s string) (time.Time, error) {
	formats := []string{
		time.RFC1123,  // Mon, 02 Jan 2006 15:04:05 MST
		time.RFC1123Z, // Mon, 02 Jan 2006 15:04:05 -0700
		time.RFC850,   // Monday, 02-Jan-06 15:04:05 MST
		time.ANSIC,    // Mon Jan _2 15:04:05 2006
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized HTTP date format: %q", s)
}

// fetchNTPTimes queries NTP servers in parallel via SNTP (RFC 4330). Each
// server gets a short UDP round-trip; unreachable or malformed responses are
// dropped.
func fetchNTPTimes(servers []string) []time.Time {
	results := make(chan time.Time, len(servers))
	for _, addr := range servers {
		go func(a string) {
			results <- queryNTP(a)
		}(addr)
	}

	var times []time.Time
	for range servers {
		select {
		case t := <-results:
			if !t.IsZero() {
				times = append(times, t)
			}
		case <-time.After(trustedTimeTimeout + time.Second):
			return times
		}
	}
	return times
}

// queryNTP sends a single SNTP v4 client request and parses the Transmit
// Timestamp field. Returns zero time on any failure.
func queryNTP(addr string) time.Time {
	conn, err := net.DialTimeout("udp", addr, trustedTimeTimeout)
	if err != nil {
		return time.Time{}
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(trustedTimeTimeout)); err != nil {
		return time.Time{}
	}

	// SNTPv4 client request: LI=0, VN=4, Mode=3 → 0x23, rest zero.
	req := make([]byte, 48)
	req[0] = 0x23
	if _, err := conn.Write(req); err != nil {
		return time.Time{}
	}

	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	if err != nil || n < 48 {
		return time.Time{}
	}

	// Transmit Timestamp is bytes 40..47, NTP epoch starts 1900-01-01.
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	if secs == 0 {
		return time.Time{}
	}
	const ntpEpochOffset = 2208988800 // seconds between 1900 and 1970
	nanos := (int64(frac) * 1e9) >> 32
	return time.Unix(int64(secs)-ntpEpochOffset, nanos).UTC()
}

// consensus returns the median of the input times if at least `minAgree`
// samples fall within `window` of each other. The returned time is the
// median of the agreeing subset — resistant to one outlier with two honest
// sources.
func consensus(times []time.Time, window time.Duration, minAgree int) (time.Time, bool) {
	if len(times) < minAgree {
		return time.Time{}, false
	}

	sorted := make([]time.Time, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Before(sorted[j])
	})

	// Sliding window: find the longest run where max-min <= window.
	bestStart, bestLen := 0, 0
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j <= len(sorted); j++ {
			if j-i <= bestLen {
				continue
			}
			if sorted[j-1].Sub(sorted[i]) <= window {
				bestStart, bestLen = i, j-i
			}
		}
	}

	if bestLen < minAgree {
		return time.Time{}, false
	}

	agreeing := sorted[bestStart : bestStart+bestLen]
	return agreeing[len(agreeing)/2], true
}
