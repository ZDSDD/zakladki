package auth

import (
	"fmt"
	"net/http"
	"strings"
)

func GetBearerToken(headers http.Header) (string, error) {
	token := headers.Get("Authorization")
	if token == "" {
		return "", fmt.Errorf("no token found in Authorization header")
	}
	tokenString, found := strings.CutPrefix(token, "Bearer ")
	if !found {
		return "", fmt.Errorf("no Bearer token found in Authorization header")
	}
	return tokenString, nil
}
