package auth

import (
	"testing"

	"github.com/google/uuid"
)

func TestJwtGenerate(t *testing.T) {
	str, err := MakeJWT(uuid.Max, "secret", 0)
	if err != nil {
		t.Errorf("Error generating JWT: %s", err)
	}
	if str == "" {
		t.Error("JWT is empty")
	}
}

func TestJwtValidate(t *testing.T) {
	token, err := MakeJWT(uuid.Max, "secret", 0)
	if err != nil {
		t.Errorf("Error generating JWT: %s", err)
	}
	userId, err := ValidateJWT(token, "secret")
	if err != nil {
		t.Errorf("Error validating JWT: %s", err)
	}
	if userId != uuid.Max {
		t.Errorf("Expected userId to be %s, got %s", uuid.Max, userId)
	}
}
