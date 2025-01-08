package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

type UserService interface {
	CreateUserWithEmailAndPassword(ctx context.Context, name, email, password string) (*User, error)
	CreateUserWithGoogle(ctx context.Context, params GoogleUserCreateParams) (*User, error)
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

func (s *defaultUserService) CreateUserWithEmailAndPassword(ctx context.Context, name, email, password string) (*User, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}

	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:            uuid.New(),
		Email:         email,
		Name:          name,
		EmailVerified: false,
		CreatedAt:     time.Now(),
	}

	_, err = s.db.CreateUser(ctx, database.CreateUserParams{
		Email:          sql.NullString{String: user.Email, Valid: true},
		Name:           user.Name,
		HashedPassword: sql.NullString{String: hashedPassword.ToString(), Valid: true},
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *defaultUserService) UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string) (*User, error) {
	if newEmail == "" {
		return nil, fmt.Errorf("email is required")
	}
	if !auth.IsEmailValid(newEmail) {
		return nil, fmt.Errorf("invalid email")
	}
	updatedUser, err := s.db.UpdateUserEmail(ctx, database.UpdateUserEmailParams{
		Email: sql.NullString{String: newEmail, Valid: true},
		ID:    userID,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return nil, fmt.Errorf("email already exists")
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
		return database.RefreshToken{}, fmt.Errorf("refresh token expired")
	}
	if rtDB.RevokedAt.Valid {
		return database.RefreshToken{}, fmt.Errorf("refresh token revoked")
	}
	return rtDB, nil
}

func (s *defaultUserService) GetUserById(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := s.db.GetUserById(ctx, id)
	if err != nil {
		return nil, err
	}
	return mapDBUserToServiceUser(&user), nil
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
	_, err := s.db.GetRefreshTokenForUser(ctx, userId)
	if err == nil {
		// Token exists, update expiration
		return s.db.UpdateExpiresAtRefreshToken(ctx, database.UpdateExpiresAtRefreshTokenParams{
			ExpiresAt: time.Now().Add(refreshTokenExpiry),
			UserID:    userId,
		})
	}

	// No existing token, create a new one
	return s.createRefreshToken(ctx, userId)
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
		return nil, errors.New(userNotFoundError)
	}
	if err := auth.CheckPasswordHash(password, auth.HashedPassword(dbUser.HashedPassword.String)); err != nil {
		return nil, errors.New(invalidPasswordError)
	}
	return mapDBUserToServiceUser(&dbUser), nil
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
