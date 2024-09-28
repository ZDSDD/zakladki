package auth

import (
	"testing"
)

func TestValidEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		// Valid email addresses
		{"test@example.com", true},
		{"user.name+tag+sorting@example.com", true},
		{"user-name@example.co.uk", true},
		{"user_name@sub.domain.example.com", true},
		{"user123@example.io", true},
		{"user@example.travel", true},

		// Invalid email addresses
		{"plainaddress", false},         // Missing '@' and domain
		{"@missing-local.com", false},   // Missing local part
		{"username@.com", false},        // Domain starts with a dot
		{"username@domain..com", false}, // Consecutive dots in domain
		{"user@@domain.com", false},     // Double '@'
		{"user@domain,com", false},      // Comma instead of dot in domain
		{"user@domain.com.", false},     // Trailing dot in domain
		{"", false},                     // Empty string
		{"   ", false},                  // Only whitespace
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := IsEmailValid(tt.email)
			if result != tt.expected {
				t.Errorf("valid(%s) = %v, expected %v", tt.email, result, tt.expected)
			}
		})
	}
}
