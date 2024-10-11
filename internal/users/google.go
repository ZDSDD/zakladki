package users

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

func (uh *UsersHandler) HandleLoginViaGoogle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}

	// Decode the request body
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		jsonUtils.RespondWithJsonError(w, "Invalid request payload: missing token", http.StatusBadRequest)
		return
	}

	// Validate Google JWT
	payload, err := auth.ValidateGoogleJWT(body.Token, os.Getenv("GOOGLE_CLIENT_ID"))
	if err != nil {
		jsonUtils.RespondWithJsonError(w, "Failed to validate token", http.StatusUnauthorized)
		return
	}

	// Check issuer
	if payload.Issuer != "https://accounts.google.com" {
		jsonUtils.RespondWithJsonError(w, fmt.Sprintf("Invalid issuer: expected 'https://accounts.google.com', got: '%s'", payload.Issuer), http.StatusBadRequest)
		return
	}

	// Check audience
	if payload.Audience != os.Getenv("GOOGLE_CLIENT_ID") {
		jsonUtils.RespondWithJsonError(w, fmt.Sprintf("Invalid audience: expected '%s', got: '%s'", os.Getenv("GOOGLE_CLIENT_ID"), payload.Audience), http.StatusUnauthorized)
		return
	}

	email, ok := extractAndValidateEmail(payload.Claims, w)
	if !ok {
		return
	}

	user, err := uh.db.GetUserByEmail(r.Context(), sql.NullString{String: email, Valid: true})

	// User exists in the db
	if err == nil {
		// User registered via email/password, now wants to link Google
		//TODO
	}

	// Example of logging user details for internal debugging
	log.Printf("Google Login: Email: %s, Name: %s, Subject: %s\n", payload.Claims["email"], payload.Claims["name"], payload.Subject)
	
	jsonUtils.RespondWithJsonError(w, mapToJson(&user, ))
}
func extractAndValidateEmail(claims map[string]interface{}, w http.ResponseWriter) (string, bool) {
	emailClaim, ok := claims["email"]
	if !ok {
		jsonUtils.RespondWithJsonError(w, "No email in the JWT", http.StatusBadRequest)
		return "", false
	}

	email, ok := emailClaim.(string)
	if !ok {
		jsonUtils.RespondWithJsonError(w, "Email claim is not a string", http.StatusBadRequest)
		return "", false
	}

	if !auth.IsEmailValid(email) {
		jsonUtils.RespondWithJsonError(w, fmt.Sprintf("Email '%s' is not valid", email), http.StatusBadRequest)
		return "", false
	}

	return email, true
}
