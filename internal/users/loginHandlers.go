package users

import (
	"net/http"
	"time"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

const (
	accessTokenExpiry  = time.Hour
	refreshTokenExpiry = 24 * time.Hour * 60 // 60 days
	refreshTokenCookie = "refresh_token"
)

func (uh *UsersHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	userReqBody, err := ExtractUserCredentials(r)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 400)
		return
	}
	var email, password = userReqBody.Email, userReqBody.Password
	email = normalizeEmail(email)
	user, err := uh.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, "User not found", http.StatusNotFound)
		return
	}

	if err := auth.CheckPasswordHash(password, user.HashedPassword); err != nil {
		jsonUtils.ResponseWithJsonError(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	token, err := auth.MakeJWT(user.ID, uh.jwtSecret, accessTokenExpiry)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var refreshToken database.RefreshToken
	_, err = uh.db.GetRefreshTokenForUser(r.Context(), user.ID)
	if err == nil { // Existing refresh token found
		refreshToken, err = uh.db.UpdateExpiresAtRefreshToken(r.Context(), database.UpdateExpiresAtRefreshTokenParams{
			ExpiresAt: time.Now().Add(refreshTokenExpiry),
			UserID:    user.ID,
		})
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		refreshTokenID, err := auth.MakeRefreshToken()
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		refreshToken, err = uh.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshTokenID,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(refreshTokenExpiry),
		})
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Set the refresh token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:        refreshTokenCookie,
		Value:       refreshToken.Token,
		Path:        "/", // or your desired path
		Expires:     time.Now().Add(refreshTokenExpiry),
		HttpOnly:    true,                  // Recommended to help prevent XSS attacks
		Secure:      true,                  // Set to true if using HTTPS
		SameSite:    http.SameSiteNoneMode, // Adjust as needed
		Partitioned: true,                  // Set to true if your application is partitioned
	})

	// Respond with user details and tokens
	jsonUtils.ResponseWithJson(mapToJson(&user, token), w, http.StatusOK)
}
