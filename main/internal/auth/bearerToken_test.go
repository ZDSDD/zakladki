package auth

import (
	"net/http"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "Bearer token")
	token, err := GetBearerToken(headers)
	if err != nil {
		t.Errorf("Error getting bearer token: %s", err)
	}
	if token != "token" {
		t.Errorf("Expected token to be 'token', got '%s'", token)
	}
}
