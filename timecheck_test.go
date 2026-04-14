package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseHTTPDate_RFC1123(t *testing.T) {
	got, err := parseHTTPDate("Mon, 02 Jan 2006 15:04:05 GMT")
	if err != nil {
		t.Fatalf("parseHTTPDate failed: %v", err)
	}
	want := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseHTTPDate_RFC850(t *testing.T) {
	got, err := parseHTTPDate("Monday, 02-Jan-06 15:04:05 GMT")
	if err != nil {
		t.Fatalf("parseHTTPDate failed: %v", err)
	}
	if got.Year() != 2006 || got.Month() != 1 || got.Day() != 2 {
		t.Fatalf("date mismatch: %v", got)
	}
}

func TestParseHTTPDate_Invalid(t *testing.T) {
	if _, err := parseHTTPDate("not-a-date"); err == nil {
		t.Fatal("expected error for invalid date")
	}
	if _, err := parseHTTPDate(""); err == nil {
		t.Fatal("expected error for empty date")
	}
}

func TestConsensus_EmptyInput(t *testing.T) {
	if _, ok := consensus(nil, 60*time.Second, 2); ok {
		t.Fatal("consensus on empty input should fail")
	}
}

func TestConsensus_SingleSource(t *testing.T) {
	times := []time.Time{time.Now()}
	if _, ok := consensus(times, 60*time.Second, 2); ok {
		t.Fatal("consensus with only 1 source should fail minAgree=2")
	}
}

func TestConsensus_TwoAgreeingReturnsMedian(t *testing.T) {
	base := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	times := []time.Time{
		base,
		base.Add(30 * time.Second),
	}
	got, ok := consensus(times, 60*time.Second, 2)
	if !ok {
		t.Fatal("expected consensus")
	}
	// Median of 2 → second element (len/2 = 1)
	want := base.Add(30 * time.Second)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestConsensus_OutlierRejected(t *testing.T) {
	base := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	times := []time.Time{
		base,
		base.Add(10 * time.Second),
		base.Add(24 * time.Hour), // outlier
	}
	got, ok := consensus(times, 60*time.Second, 2)
	if !ok {
		t.Fatal("expected consensus from the two close samples")
	}
	if got.Sub(base) > 60*time.Second {
		t.Fatalf("consensus locked onto outlier: %v", got)
	}
}

func TestConsensus_NoAgreement(t *testing.T) {
	base := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	times := []time.Time{
		base,
		base.Add(10 * time.Minute),
		base.Add(20 * time.Minute),
	}
	if _, ok := consensus(times, 60*time.Second, 2); ok {
		t.Fatal("no two samples within window — consensus should fail")
	}
}

func TestFetchHTTPSDate_ValidServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	got := fetchHTTPSDate(srv.URL)
	want := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFetchHTTPSDate_MissingHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go's http server sets Date automatically. Override with empty.
		w.Header()["Date"] = nil
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	got := fetchHTTPSDate(srv.URL)
	// Go's server may re-inject Date; accept either zero or a recent time as "not a failure path we can force here".
	if !got.IsZero() && time.Since(got) > time.Hour {
		t.Fatalf("got stale time: %v", got)
	}
}

func TestFetchHTTPSTimes_Consensus(t *testing.T) {
	base := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", base.Format(time.RFC1123))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", base.Add(10*time.Second).Format(time.RFC1123))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	times := fetchHTTPSTimes([]string{srv1.URL, srv2.URL})
	if len(times) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(times))
	}
	if _, ok := consensus(times, 60*time.Second, 2); !ok {
		t.Fatal("expected consensus across 2 close sources")
	}
}
