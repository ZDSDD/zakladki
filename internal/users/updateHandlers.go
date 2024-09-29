package users

import (
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
	json.NewDecoder(r.Body).Decode(&userReq)
	if userReq.Email == "" {
		jsonUtils.ResponseWithJsonError(w, "Email is required", 400)
		return
	}
	if !auth.IsEmailValid(userReq.Email) {
		jsonUtils.ResponseWithJsonError(w, "Invalid email", 400)
		return
	}
	userId, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 401)
		return
	}

	updatedUser, err := uh.db.UpdateUserEmail(r.Context(), database.UpdateUserEmailParams{
		Email: userReq.Email,
		ID:    userId,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			jsonUtils.ResponseWithJsonError(w, "Email already exists", 403)
			return
		}
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	jsonUtils.ResponseWithJson(mapToJson(&updatedUser, "", ""), w, 201)
}

func (uh *UsersHandler) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	type UserReqBody struct {
		Password string `json:"password"`
	}
	var userReq UserReqBody
	json.NewDecoder(r.Body).Decode(&userReq)
	if userReq.Password == "" {
		jsonUtils.ResponseWithJsonError(w, "password is required", 400)
		return
	}
	if err := auth.CheckPasswordStrength(userReq.Password, uh.minPasswordEntropy); err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 400)
		return
	}

	hashesPassword, err := auth.HashPassword(userReq.Password)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	userID, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 401)
		return
	}

	updatedUser, err := uh.db.UpdateUserPassword(r.Context(), database.UpdateUserPasswordParams{
		HashedPassword: hashesPassword,
		ID:             userID,
	})
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	jsonUtils.ResponseWithJson(mapToJson(&updatedUser, "", ""), w, 201)
}
