package users

import (
	"net/http"
	"time"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

func (uh *UsersHandler) handleLogin(w http.ResponseWriter, r *http.Request, email, password string) {
	user, err := uh.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	if err := auth.CheckPasswordHash(password, user.HashedPassword); err != nil {
		jsonUtils.ResponseWithJsonError(w, "Invalid password", 401)
		return
	}

	token, err := auth.MakeJWT(user.ID, uh.jwtSecret, time.Hour)

	var refreshToken database.RefreshToken
	_, err = uh.db.GetRefreshTokenForUser(r.Context(), user.ID)
	if err == nil { //There is already refresh token for this user in the database.
		refreshToken, err = uh.db.UpdateExpiresAtRefreshToken(r.Context(), database.UpdateExpiresAtRefreshTokenParams{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
			UserID:    user.ID,
		})
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
			return
		}

	} else {
		refreshTokenID, err := auth.MakeRefreshToken()
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
			return
		}
		refreshToken, err = uh.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshTokenID,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
	}
	jsonUtils.ResponseWithJson(mapToJson(&user, token, refreshToken.Token), w, http.StatusOK)
}
