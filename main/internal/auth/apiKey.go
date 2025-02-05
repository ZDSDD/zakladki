package auth

import (
	"errors"
	"net/http"
	"strings"
)

func GetAPIKey(headers http.Header) (string, error) {
	apiKey := headers.Get("Authorization")
	if apiKey == "" {
		return "", errors.New("API key is required")
	}
	apiKey, found := strings.CutPrefix(apiKey, "ApiKey ")
	if !found {
		return "", errors.New("API key must be prefixed with 'ApiKey'. ApiKey <key>")
	}
	return apiKey, nil
}
