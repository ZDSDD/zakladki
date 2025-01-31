package users

import (
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
		jsonUtils.RespondWithJsonError(w, "Invalid email in the JWT", http.StatusBadRequest)
		return
	}

	user, err := uh.us.GetUserByEmail(r.Context(), email)
	// User exists in the db
	userName, ok := payload.Claims["name"].(string)
	if !ok {
		jsonUtils.RespondWithJsonError(w, "Name claim is not a string", http.StatusBadRequest)
		return
	}

	if err == nil {
		// User registered via email/password, now wants to link Google
		//TODO
	} else if err.Error() == "sql: no rows in result set" {
		// User is not found in the db
		// Create new google user and save it to the db
		user, err = uh.us.CreateUserWithGoogle(r.Context(), GoogleUserCreateParams{Email: email, UserGooglesId: payload.Subject, Name: userName})
	} else {
		//something else went wrong
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
	}
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	log.Printf("Google Login: Email: %s, Name: %s, Subject: %s\n", payload.Claims["email"], payload.Claims["name"], payload.Subject)
	uh.respondWithJWTToken(user, w, r)
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
