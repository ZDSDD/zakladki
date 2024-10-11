package users

import (
	"database/sql"
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

// TODO: handle scenarios when user uses 3rd party login
func (uh *UsersHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	userReqBody, err := ExtractUserCredentials(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}
	var email, password = userReqBody.Email, userReqBody.Password
	email = normalizeEmail(email)
	user, err := uh.db.GetUserByEmail(r.Context(), sql.NullString{String: email, Valid: true})
	if err != nil {
		jsonUtils.RespondWithJsonError(w, "User not found", http.StatusNotFound)
		return
	}

	if err := auth.CheckPasswordHash(password, user.HashedPassword.String); err != nil {
		jsonUtils.RespondWithJsonError(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	token, err := newFunction(user, uh, w, r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonUtils.ResponseWithJson(mapToJson(&user, token), w, http.StatusOK)
}

func newFunction(user database.User, uh *UsersHandler, w http.ResponseWriter, r *http.Request) (token string, err error) {
	token, err = auth.MakeJWT(user.ID, uh.jwtSecret, accessTokenExpiry)
	if err != nil {
		return "", err
	}

	var refreshToken database.RefreshToken
	_, err = uh.db.GetRefreshTokenForUser(r.Context(), user.ID)
	if err == nil {
		refreshToken, err = uh.db.UpdateExpiresAtRefreshToken(r.Context(), database.UpdateExpiresAtRefreshTokenParams{
			ExpiresAt: time.Now().Add(refreshTokenExpiry),
			UserID:    user.ID,
		})
		if err != nil {
			return "", err
		}
	} else {
		refreshTokenID, err := auth.MakeRefreshToken()
		if err != nil {
			return "", err
		}
		refreshToken, err = uh.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshTokenID,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(refreshTokenExpiry),
		})
		if err != nil {
			return "", err
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:        refreshTokenCookie,
		Value:       refreshToken.Token,
		Path:        "/",
		Expires:     time.Now().Add(refreshTokenExpiry),
		HttpOnly:    true, // Recommended to help prevent XSS attacks
		Secure:      true, // Set to true if using HTTPS
		SameSite:    http.SameSiteNoneMode,
		Partitioned: true,
	})

	return token, nil
}
