package users

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

func (uh *UsersHandler) handleUpdateEmail(w http.ResponseWriter, r *http.Request) {
	type UserReqBody struct {
		Email string `json:"email"`
	}
	var userReq UserReqBody
	err := json.NewDecoder(r.Body).Decode(&userReq)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	if userReq.Email == "" {
		jsonUtils.RespondWithJsonError(w, "Email is required", 400)
		return
	}
	if !auth.IsEmailValid(userReq.Email) {
		jsonUtils.RespondWithJsonError(w, "Invalid email", 400)
		return
	}
	userId, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 401)
		return
	}

	updatedUser, err := uh.db.UpdateUserEmail(r.Context(), database.UpdateUserEmailParams{
		Email: sql.NullString{String: userReq.Email, Valid: true},
		ID:    userId,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			jsonUtils.RespondWithJsonError(w, "Email already exists", 403)
			return
		}
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	jsonUtils.ResponseWithJson(mapToJson(&updatedUser, ""), w, 201)
}

func (uh *UsersHandler) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	type UserReqBody struct {
		Password string `json:"password"`
	}
	var userReq UserReqBody
	err := json.NewDecoder(r.Body).Decode(&userReq)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	if userReq.Password == "" {
		jsonUtils.RespondWithJsonError(w, "password is required", 400)
		return
	}
	if err := auth.CheckPasswordStrength(userReq.Password, uh.minPasswordEntropy); err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}

	hashesPassword, err := auth.HashPassword(userReq.Password)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	userID, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 401)
		return
	}

	updatedUser, err := uh.db.UpdateUserPassword(r.Context(), database.UpdateUserPasswordParams{
		HashedPassword: sql.NullString{String: hashesPassword, Valid: true},
		ID:             userID,
	})
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	jsonUtils.ResponseWithJson(mapToJson(&updatedUser, ""), w, 201)
}
