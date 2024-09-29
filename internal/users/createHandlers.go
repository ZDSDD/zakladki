package users

import (
	"net/http"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

func (uh *UsersHandler) handleCreateUser(w http.ResponseWriter, r *http.Request, email, password string) {

	_, err := uh.db.GetUserByEmail(r.Context(), email)
	if err == nil {
		jsonUtils.ResponseWithJsonError(w, "User already exists", 400)
		return
	}
	if !auth.IsEmailValid(email) {
		jsonUtils.ResponseWithJsonError(w, "Invalid email", 400)
		return
	}
	if err := auth.CheckPasswordStrength(password, uh.minPasswordEntropy); err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 400)
		return
	}
	hashedPasswd, err := auth.HashPassword(password)

	user, err := uh.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          email,
		HashedPassword: hashedPasswd,
	})
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(mapToJson(&user, "", ""), w, http.StatusCreated)
}
