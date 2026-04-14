package main

import (
	"strings"
	"testing"
)

func TestValidatePassphrase_TooShort(t *testing.T) {
	if err := ValidatePassphrase("Aa1!"); err == nil {
		t.Fatal("expected too-short to fail")
	} else if !strings.Contains(err.Error(), "12 characters") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePassphrase_MissingClasses(t *testing.T) {
	tests := []struct {
		pass string
		want PassphraseIssue
	}{
		{"abcdefghij12!", IssueNoUppercase},
		{"ABCDEFGHIJ12!", IssueNoLowercase},
		{"Abcdefghijkl!", IssueNoDigit},
		{"Abcdefghij123", IssueNoSpecial},
	}
	for _, tc := range tests {
		issues := PassphraseIssues(tc.pass)
		found := false
		for _, it := range issues {
			if it == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: expected issue %q, got %v", tc.pass, tc.want, issues)
		}
	}
}

func TestValidatePassphrase_CommonBlocked(t *testing.T) {
	if err := ValidatePassphrase("Password123!"); err == nil {
		t.Fatal("expected 'Password123!' to be blocked as common")
	} else if !strings.Contains(err.Error(), "blocklist") {
		t.Fatalf("expected blocklist mention, got %v", err)
	}

	// Case-insensitive match
	if err := ValidatePassphrase("pAsSwOrD123!"); err == nil {
		t.Fatal("expected case-insensitive blocklist match")
	}
}

func TestValidatePassphrase_Accepts(t *testing.T) {
	good := []string{
		"Tr0ub4dor&3xample",
		"MyDog!Eats#7Biscuits",
		"Sunset@Mountain9Pine",
	}
	for _, p := range good {
		if err := ValidatePassphrase(p); err != nil {
			t.Errorf("expected %q to pass, got %v", p, err)
		}
	}
}

func TestPassphraseStrength_Weak(t *testing.T) {
	cases := []string{"", "short", "abc", "12345"}
	for _, p := range cases {
		score, label := PassphraseStrength(p)
		if score != 0 || label != "weak" {
			t.Errorf("%q: expected weak/0, got %q/%d", p, label, score)
		}
	}
}

func TestPassphraseStrength_MeetsMinimum(t *testing.T) {
	score, label := PassphraseStrength("Abcdefgh123!") // exactly 12 chars, 4 classes
	if score < 2 {
		t.Errorf("expected >=good, got %q/%d", label, score)
	}
}

func TestPassphraseStrength_Strong(t *testing.T) {
	score, label := PassphraseStrength("MyDog!Eats#7Biscuits") // 20 chars, 4 classes, varied
	if score < 3 {
		t.Errorf("expected strong+ for 20-char diverse pass, got %q/%d", label, score)
	}
}

func TestPassphraseStrength_BlocklistedCapped(t *testing.T) {
	// Would otherwise score well on surface metrics — blocklist caps at fair.
	score, _ := PassphraseStrength("Password123!")
	if score > 1 {
		t.Errorf("blocklisted pass should cap at fair, got %d", score)
	}
}

func TestPassphraseStrength_VeryStrong(t *testing.T) {
	// 22 chars, all classes, high uniqueness
	pass := "Correct!Horse7Battery@Staple"
	score, label := PassphraseStrength(pass)
	if score < 3 {
		t.Errorf("expected strong+ for diverse long pass, got %q/%d (pass=%q)", label, score, pass)
	}
}

func TestValidatePassphrase_EmptyReportsAllCore(t *testing.T) {
	// An empty pass fails length + all 4 class rules. Blocklist is not hit.
	issues := PassphraseIssues("")
	if len(issues) < 5 {
		t.Errorf("expected at least 5 issues for empty pass, got %d: %v", len(issues), issues)
	}
}
