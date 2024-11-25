package users

import (
	"encoding/json"
	"net/http"

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

	userId, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 401)
		return
	}

	updatedUser, err := uh.us.UpdateUserEmail(r.Context(), userId, userReq.Email)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	jsonUtils.ResponseWithJson(MapUserToResponse(updatedUser), w, 201)
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

	userID, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 401)
		return
	}

	updatedUser, err := uh.us.UpdateUserPassword(r.Context(), userID, userReq.Password)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	jsonUtils.ResponseWithJson(MapUserToResponse(updatedUser), w, 201)
}
