package users

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

// make email lowercase
func normalizeEmail(email string) string {
	return strings.ToLower(email)
}

func (uh *UsersHandler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	userReqBody, err := ExtractUserCredentials(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}

	var email, password, name string = userReqBody.Email, userReqBody.Password, userReqBody.Name
	if name == "" {
		jsonUtils.RespondWithJsonError(w, "Name is required", 400)
		return
	}
	email = normalizeEmail(email)
	_, err = uh.db.GetUserByEmail(r.Context(), sql.NullString{String: email, Valid: true})
	if err == nil {
		jsonUtils.RespondWithJsonError(w, "User already exists", 400)
		return
	}
	if !auth.IsEmailValid(email) {
		jsonUtils.RespondWithJsonError(w, "Invalid email", 400)
		return
	}
	if err := auth.CheckPasswordStrength(password, uh.minPasswordEntropy); err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}
	hashedPasswd, err := auth.HashPassword(password)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}

	user, err := uh.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          sql.NullString{String: email, Valid: true},
		HashedPassword: sql.NullString{String: hashedPasswd, Valid: true},
		Name:           name,
	})
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(mapToJson(&user, ""), w, http.StatusCreated)
}
