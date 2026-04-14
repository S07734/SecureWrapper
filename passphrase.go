package main

import (
	"fmt"
	"strings"
	"unicode"
)

const minPassphraseLen = 12

// commonPassphrases is a curated blocklist of phrases that pass the length
// and class-diversity rules but are widely known to be weak (top breach
// corpora, obvious keyboard walks, year-appended defaults). Kept short on
// purpose — the 12-char minimum and class requirements already filter the
// long tail of common passwords.
var commonPassphrases = func() map[string]struct{} {
	list := []string{
		// Password + suffix patterns
		"password1234", "password12345", "password123!", "password1!", "password123",
		"Password1234", "Password12345", "Password123!", "Password1!", "Password123",
		"Password2023!", "Password2024!", "Password2025!", "Password2026!",
		"P@ssword1234", "P@ssw0rd1234", "Pa$$word1234", "Pa$$w0rd1234",

		// Keyboard walks + year
		"Qwerty123456", "Qwerty1234!", "Qwerty12345!", "qwerty123456",
		"1qaz2wsx3edc", "1q2w3e4r5t6y", "zaq12wsxcde3",

		// Welcome/Admin/Login + year
		"Welcome1234", "Welcome12345", "Welcome123!", "Welcome2024!", "Welcome2025!", "Welcome2026!",
		"Admin1234567", "Admin12345678", "Administrator", "Administrator1",
		"Letmein1234", "Letmein12345", "Letmein123!",

		// Month/season + year + !
		"Summer2024!!", "Summer2025!!", "Summer2026!!", "Spring2024!!", "Autumn2024!!", "Winter2024!!",
		"Summer2024!", "Summer2025!", "Summer2026!", "Spring2025!", "Autumn2025!", "Winter2025!",

		// "I love you"/affection phrases + punctuation
		"Iloveyou2024!", "Iloveyou1234", "IloveYou123!", "Iloveyou123!",

		// Famous weak phrases at length
		"Changeme1234", "Changeme123!", "Trustno1234!", "Monkey123456",
		"Dragon123456", "Princess1234", "Superman1234", "Batman123456",

		// Character substitution classics
		"P@ssw0rd2024", "P@ssw0rd2025", "P@ssw0rd2026", "P@ssw0rd1!",
	}
	m := make(map[string]struct{}, len(list))
	for _, p := range list {
		m[strings.ToLower(p)] = struct{}{}
	}
	return m
}()

// PassphraseIssue describes a single failed rule. Callers may show all issues
// at once rather than surface them one at a time.
type PassphraseIssue string

const (
	IssueTooShort      PassphraseIssue = "must be at least 12 characters"
	IssueNoUppercase   PassphraseIssue = "must contain an uppercase letter"
	IssueNoLowercase   PassphraseIssue = "must contain a lowercase letter"
	IssueNoDigit       PassphraseIssue = "must contain a digit"
	IssueNoSpecial     PassphraseIssue = "must contain a special character"
	IssueCommon        PassphraseIssue = "is on the common-password blocklist — choose something less predictable"
)

// ValidatePassphrase returns nil if the passphrase meets the hard policy, or
// a combined error listing every rule it fails.
func ValidatePassphrase(pass string) error {
	issues := PassphraseIssues(pass)
	if len(issues) == 0 {
		return nil
	}
	parts := make([]string, 0, len(issues))
	for _, it := range issues {
		parts = append(parts, string(it))
	}
	return fmt.Errorf("passphrase %s", strings.Join(parts, "; "))
}

// PassphraseIssues lists every rule the passphrase fails, in order. Empty
// slice means the passphrase is acceptable. Useful for UIs that want to show
// all failures at once.
func PassphraseIssues(pass string) []PassphraseIssue {
	var issues []PassphraseIssue
	if len(pass) < minPassphraseLen {
		issues = append(issues, IssueTooShort)
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range pass {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSpace(r):
			// spaces don't count as special but aren't forbidden
		default:
			// anything non-alnum non-space treated as special (punct, symbols)
			hasSpecial = true
		}
	}
	if !hasUpper {
		issues = append(issues, IssueNoUppercase)
	}
	if !hasLower {
		issues = append(issues, IssueNoLowercase)
	}
	if !hasDigit {
		issues = append(issues, IssueNoDigit)
	}
	if !hasSpecial {
		issues = append(issues, IssueNoSpecial)
	}
	if _, blocked := commonPassphrases[strings.ToLower(pass)]; blocked {
		issues = append(issues, IssueCommon)
	}
	return issues
}

// PassphraseStrength returns an advisory 0..4 score and a human label.
// The score is independent of PassphraseIssues — a passphrase can fail hard
// rules while still scoring low, and pass hard rules while scoring mid.
//
//	0 weak        — too short or ≤1 class
//	1 fair        — meets minimum, limited diversity
//	2 good        — 12+ chars, 3+ classes, decent unique-char ratio
//	3 strong      — 16+ chars, all 4 classes
//	4 very strong — 20+ chars, all 4 classes, high uniqueness
func PassphraseStrength(pass string) (int, string) {
	if pass == "" {
		return 0, "weak"
	}

	classes := 0
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	uniq := make(map[rune]struct{})
	for _, r := range pass {
		uniq[r] = struct{}{}
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case !unicode.IsSpace(r):
			hasSpecial = true
		}
	}
	for _, b := range []bool{hasUpper, hasLower, hasDigit, hasSpecial} {
		if b {
			classes++
		}
	}

	n := len(pass)
	uniqRatio := float64(len(uniq)) / float64(n)

	score := 0
	switch {
	case n < minPassphraseLen:
		return 0, "weak"
	case n >= 20 && classes == 4 && uniqRatio >= 0.6:
		score = 4
	case n >= 16 && classes == 4:
		score = 3
	case n >= 12 && classes >= 3 && uniqRatio >= 0.5:
		score = 2
	case n >= 12:
		score = 1
	default:
		score = 0
	}

	// Blocklisted passphrases cap at "fair" regardless of surface metrics.
	if _, blocked := commonPassphrases[strings.ToLower(pass)]; blocked && score > 1 {
		score = 1
	}

	return score, strengthLabel(score)
}

func strengthLabel(score int) string {
	switch score {
	case 4:
		return "very strong"
	case 3:
		return "strong"
	case 2:
		return "good"
	case 1:
		return "fair"
	default:
		return "weak"
	}
}
