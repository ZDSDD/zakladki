package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
)

// User represents a user in the business logic layer
type User struct {
	ID            uuid.UUID
	Email         string
	Name          string
	Role          Role
	EmailVerified bool
	CreatedAt     time.Time
}
type AuthProvider string

const (
	ProviderGoogle   AuthProvider = "google"
	ProviderFacebook AuthProvider = "facebook"
)

type EmailAndPasswordAuthOption struct {
	email          string
	HashedPassword auth.HashedPassword
}

type ThirdPartyAuthOption struct {
	Provider   AuthProvider // "google", "facebook", etc.
	ProviderID string       // Third-party provider user ID
}

type AuthOptions struct {
	EmailAndPasswordOption *EmailAndPasswordAuthOption // Only for password-based login
	ThirdPartyOption       *ThirdPartyAuthOption
}

type UserService interface {
	CreateUser(ctx context.Context, name string, authOptions AuthOptions) (*User, error)
	GetUser(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserById(ctx context.Context, id uuid.UUID) (*User, error)
	GetRefreshTokenForUser(ctx context.Context, userId uuid.UUID) (database.RefreshToken, error)
	AuthenticateUserByEmailAndPassword(ctx context.Context, email, password string) (*User, error)
	UpdateUserPassword(ctx context.Context, userId uuid.UUID, rawPassword string) (*User, error)
	GetRefreshToken(ctx context.Context, refreshT string) (database.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, refreshT string) error
	UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string) (*User, error)
}

type defaultUserService struct {
	db                 *database.Queries
	minPasswordEntropy float64
}

func (s *defaultUserService) UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string) (*User, error) {
	if newEmail == "" {
		return nil, fmt.Errorf("Email is required")
	}
	if !auth.IsEmailValid(newEmail) {
		return nil, fmt.Errorf("Invalid email")
	}
	updatedUser, err := s.db.UpdateUserEmail(ctx, database.UpdateUserEmailParams{
		Email: sql.NullString{String: newEmail, Valid: true},
		ID:    userID,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return nil, fmt.Errorf("Email already exists")
		}
		return nil, err
	}
	return mapDBUserToServiceUser(&updatedUser), nil
}
func (s *defaultUserService) RevokeRefreshToken(ctx context.Context, refreshT string) error {
	return s.db.RevokeRefreshToken(ctx, refreshT)
}

func (s *defaultUserService) GetRefreshToken(ctx context.Context, refreshT string) (database.RefreshToken, error) {
	rtDB, err := s.db.GetRefreshToken(ctx, refreshT)
	if err != nil {
		return database.RefreshToken{}, err
	}
	if rtDB.ExpiresAt.Before(time.Now()) {
		return database.RefreshToken{}, fmt.Errorf("Refresh token expired")
	}
	if rtDB.RevokedAt.Valid {
		return database.RefreshToken{}, fmt.Errorf("Refresh token revoked")
	}
	return rtDB, nil
}

func (s *defaultUserService) GetUserById(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := s.GetUserById(ctx, id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *defaultUserService) UpdateUserPassword(ctx context.Context, userId uuid.UUID, rawPassword string) (*User, error) {
	if rawPassword == "" {
		return nil, fmt.Errorf("password is an empty string")
	}

	if err := auth.CheckPasswordStrength(rawPassword, s.minPasswordEntropy); err != nil {
		return nil, err
	}

	hashesPassword, err := auth.HashPassword(rawPassword)
	if err != nil {
		return nil, err
	}
	usr, err := s.db.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
		HashedPassword: sql.NullString{String: hashesPassword.ToString(), Valid: true},
		ID:             userId,
	})
	if err != nil {
		return nil, err
	}
	return mapDBUserToServiceUser(&usr), nil
}

func (s *defaultUserService) GetRefreshTokenForUser(ctx context.Context, userId uuid.UUID) (database.RefreshToken, error) {
	refreshToken, err := s.db.GetRefreshTokenForUser(ctx, userId)
	if err == nil {
		refreshToken, err = s.db.UpdateExpiresAtRefreshToken(ctx, database.UpdateExpiresAtRefreshTokenParams{
			ExpiresAt: time.Now().Add(refreshTokenExpiry),
			UserID:    userId,
		})
		if err != nil {
			return database.RefreshToken{}, err
		}
	} else {
		refreshToken, err = s.createRefreshToken(ctx, userId)
		if err != nil {
			return database.RefreshToken{}, err
		}
	}
	return refreshToken, nil
}

func (us *defaultUserService) createRefreshToken(c context.Context, userId uuid.UUID) (database.RefreshToken, error) {
	refreshTokenID, err := auth.MakeRefreshToken()
	if err != nil {
		return database.RefreshToken{}, err
	}
	rt, err := us.db.CreateRefreshToken(c, database.CreateRefreshTokenParams{
		Token:     refreshTokenID,
		UserID:    userId,
		ExpiresAt: time.Now().Add(refreshTokenExpiry),
	})
	if err != nil {
		return database.RefreshToken{}, err
	}
	return rt, nil
}

const (
	userNotFoundError    = "user not found"
	invalidPasswordError = "invalid password"
)

func (s *defaultUserService) AuthenticateUserByEmailAndPassword(ctx context.Context, email, password string) (*User, error) {
	email = normalizeEmail(email)
	dbUser, err := s.db.GetUserByEmail(ctx, sql.NullString{String: email, Valid: true})
	if err != nil {
		return nil, fmt.Errorf(userNotFoundError)
	}
	if err := auth.CheckPasswordHash(password, auth.HashedPassword(dbUser.HashedPassword.String)); err != nil {
		return nil, fmt.Errorf(invalidPasswordError)
	}
	return mapDBUserToServiceUser(&dbUser), nil
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

type UsersHandler struct {
	us                 UserService
	jwtSecret          string
	minPasswordEntropy float64
}

func NewUserHandler(db *database.Queries, jwtSecret string, minPasswordEntropy float64) *UsersHandler {
	us := &defaultUserService{
		db:                 db,
		minPasswordEntropy: minPasswordEntropy,
	}
	return &UsersHandler{
		us:        us,
		jwtSecret: jwtSecret,
	}
}

type UserReqBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func ExtractUserCredentials(r *http.Request) (userReq UserReqBody, err error) {
	err = json.NewDecoder(r.Body).Decode(&userReq)
	if err != nil {
		return userReq, err
	}
	if userReq.Email == "" {
		return userReq, fmt.Errorf("email is required")
	}
	if userReq.Password == "" {
		return userReq, fmt.Errorf("password is required")
	}
	if userReq.Name == "" {
		// return userReq, fmt.Errorf("Name is required")
	}
	return userReq, nil
}
func (uh *UsersHandler) UsersRouter() http.Handler {
	// User-related routes
	r := chi.NewRouter()

	r.Post("/", uh.handleCreateUser)
	r.Post("/login", uh.handleLogin)
	r.Post("/google", uh.HandleLoginViaGoogle)

	// mux.HandleFunc("PUT /api/users", uh.requireBearerToken(uh.handleUpdateUser))
	r.Put("/password", uh.RequireValidJWTToken(http.HandlerFunc(uh.handleUpdatePassword)))
	r.Put("/email", uh.RequireValidJWTToken(http.HandlerFunc(uh.handleUpdateEmail)))

	// JWT-related routers
	r.Post("/refresh", uh.RequireValidJWTToken(http.HandlerFunc(uh.handleRefreshToken)))
	r.Post("/revoke", uh.requireBearerToken(http.HandlerFunc(uh.handleRevokeToken)))
	return r
}

// Helper function to get user ID from context
func GetUserIDFromContext(r *http.Request) (uuid.UUID, error) {
	userId, ok := r.Context().Value(UserIDKey).(uuid.UUID)
	if !ok || userId == uuid.Nil {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return userId, nil
}

// Helper function to get user ID from context
func GetBearerTokenFromContext(r *http.Request) (string, error) {
	userId, ok := r.Context().Value(TokenKey).(string)
	if !ok || userId == "" {
		return "", fmt.Errorf("JWT Token not found in context")
	}
	return userId, nil
}

type UserResponse struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type AuthResponse struct {
	User  UserResponse `json:"user"`
	Token string       `json:"token,omitempty"`
}

// MapUserToResponse converts a User model to a UserResponse
func MapUserToResponse(u *User) UserResponse {
	return UserResponse{
		ID:   u.ID,
		Name: u.Name,
	}
}

// MapUserToAuthResponse converts a User model and token to an AuthResponse
func MapUserToAuthResponse(u *User, token string) AuthResponse {
	return AuthResponse{
		User:  MapUserToResponse(u),
		Token: token,
	}
}

// Helper function to map DB user to service user
func mapDBUserToServiceUser(dbUser *database.User) *User {
	return &User{
		ID:            dbUser.ID,
		Email:         dbUser.Email.String,
		Name:          dbUser.Name,
		Role:          Role(dbUser.Role),
		EmailVerified: dbUser.EmailVerified,
		CreatedAt:     dbUser.CreatedAt,
	}
}
