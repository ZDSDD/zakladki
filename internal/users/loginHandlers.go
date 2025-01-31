package users

import (
	"net/http"
	"time"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

const (
	accessTokenExpiry  = time.Hour
	refreshTokenExpiry = 24 * time.Hour * 60 // 60 days
	refreshTokenCookie = "refresh_token"
)

// TODO: handle scenarios when user uses 3rd party login
func (uh *UsersHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	userReqBody, err := ExtractUserCredentialsLogin(r)

	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}
	var email, password = userReqBody.Email, userReqBody.Password
	user, err := uh.us.AuthenticateUserByEmailAndPassword(r.Context(), email, password)
	if err != nil {
		if err.Error() == userNotFoundError {
			jsonUtils.RespondWithJsonError(w, userNotFoundError, http.StatusNotFound)
			return
		} else if err.Error() == invalidPasswordError {
			jsonUtils.RespondWithJsonError(w, "Invalid password", http.StatusUnauthorized)
			return
		} else {
			jsonUtils.RespondWithJsonError(w, "Unexpected error occurred", http.StatusInternalServerError)
			return
		}
	}
	uh.respondWithJWTToken(user, w, r)
}

func (uh *UsersHandler) respondWithJWTToken(user *User, w http.ResponseWriter, r *http.Request) {
	token, err := auth.MakeJWT(user.ID, uh.jwtSecret, accessTokenExpiry)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	refreshToken, err := uh.us.GetRefreshTokenForUser(r.Context(), user.ID)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
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
	jsonUtils.ResponseWithJson(MapUserToAuthResponse(user, token), w, http.StatusOK)
}
