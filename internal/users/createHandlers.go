package users

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
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
	if err := auth.CheckPasswordStrength(password, uh.minPasswordEntropy); err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 400)
		return
	}
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	user, err := uh.us.CreateUser(r.Context(), name, AuthOptions{EmailAndPasswordOption: &EmailAndPasswordAuthOption{email: email, HashedPassword: hashedPassword}})
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(MapUserToResponse(user), w, http.StatusCreated)
}

func (us *defaultUserService) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("email was empty")
	}
	email = normalizeEmail(email)
	dbUser, err := us.db.GetUserByEmail(ctx, sql.NullString{String: email, Valid: true})
	if err != nil {
		return nil, err
	}
	return mapDBUserToServiceUser(&dbUser), nil
}

func (us *defaultUserService) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	dbUser, err := us.db.GetUserById(ctx, id)
	if err != nil {
		return nil, err
	}
	return mapDBUserToServiceUser(&dbUser), nil
}

func CreateUserWithEmailAndPasswordStrategy(s *defaultUserService, ctx context.Context, name string, option EmailAndPasswordAuthOption) (*User, error) {
	// Check if a user with this email already exits
	var email string = option.email
	var password auth.HashedPassword = option.HashedPassword

	_, err := s.GetUserByEmail(ctx, email)
	if err == nil {
		return nil, fmt.Errorf("User already exists")
	}
	if !auth.IsEmailValid(email) {
		return nil, fmt.Errorf("Invalid email")
	}
	user, err := s.db.CreateUser(ctx, database.CreateUserParams{
		Email:          sql.NullString{String: email, Valid: true},
		HashedPassword: sql.NullString{String: password.ToString(), Valid: true},
		Name:           name,
	})
	if err != nil {
		return nil, err
	}
	return &User{ID: user.ID}, nil
}

func CreateUserWithGoogleStrategy(s *defaultUserService, ctx context.Context, name string, option ThirdPartyAuthOption) (*User, error) {
	// Check if user already exits
	provider := option.Provider
	userProviderId := option.ProviderID

	_, err := s.db.GetUserByProvider(ctx, database.GetUserByProviderParams{
		Provider:       database.AuthProvider(provider),
		ProviderUserID: userProviderId,
	})
	// User already in the db
	if err == nil {
		return nil, fmt.Errorf("user already exist")
	}
	// If user doesn't exits, create an account
	userdb, err := s.db.CreateUser(ctx, database.CreateUserParams{
		Name: name,
	})
	if err != nil {
		return nil, err
	}
	_, err = s.db.CreateUserWithProvider(ctx, database.CreateUserWithProviderParams{
		UserID:         userdb.ID,
		ProviderUserID: userProviderId,
		Provider:       database.AuthProvider(provider),
	})
	if err != nil {
		return nil, err
	}
	return mapDBUserToServiceUser(&userdb), nil
}

func (s *defaultUserService) CreateUser(ctx context.Context, name string, authOptions AuthOptions) (*User, error) {
	if name == "" {
		return nil, fmt.Errorf("Name is required")
	}
	if authOptions.EmailAndPasswordOption != nil {
		return CreateUserWithEmailAndPasswordStrategy(s, ctx, name, *authOptions.EmailAndPasswordOption)
	}
	// Handle third-party provider registration
	if authOptions.ThirdPartyOption != nil {
		switch authOptions.ThirdPartyOption.Provider {
		case ProviderGoogle:
			return CreateUserWithGoogleStrategy(s, ctx, name, *authOptions.ThirdPartyOption)
		// Add other providers here (e.g., Facebook)
		default:
			return nil, fmt.Errorf("unsupported provider: %s", authOptions.ThirdPartyOption.Provider)
		}
	}

	return nil, fmt.Errorf("invalid auth options")
}
