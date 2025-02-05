package users

import (
	"context"
	"database/sql"
	"fmt"
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
	userReqBody, err := ExtractUserCredentialsLogin(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}

	var email, password, name string = userReqBody.Email, userReqBody.Password, userReqBody.Name
	if err := auth.CheckPasswordStrength(password, uh.minPasswordEntropy); err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}
	user, err := uh.us.CreateUserWithEmailAndPassword(r.Context(), name, email, password)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(MapUserToResponse(user), w, http.StatusCreated)
}

type GoogleUserCreateParams struct {
	Email         string
	UserGooglesId string
	Name          string
}

func (us *defaultUserService) CreateUserWithGoogle(ctx context.Context, params GoogleUserCreateParams) (*User, error) {
	// Check if user already exits
	provider := ProviderGoogle

	_, err := us.db.GetUserByProvider(ctx, database.GetUserByProviderParams{
		Provider:       database.AuthProvider(provider),
		ProviderUserID: params.UserGooglesId,
	})
	// User already in the db
	if err == nil {
		return nil, fmt.Errorf("user already exist")
	}
	// If user doesn't exits, create an account
	userdb, err := us.db.CreateUser(ctx, database.CreateUserParams{
		Email: sql.NullString{Valid: true, String: params.Email},
		Name:  params.Name,
	})
	if err != nil {
		return nil, err
	}
	_, err = us.db.CreateUserWithProvider(ctx, database.CreateUserWithProviderParams{
		UserID:         userdb.ID,
		ProviderUserID: params.UserGooglesId,
		Provider:       database.AuthProvider(provider),
	})
	if err != nil {
		return nil, err
	}
	return mapDBUserToServiceUser(&userdb), nil
}
