package users

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
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

type UserService interface {
	CreateUser(user User) error
	GetUser(id string) (User, error)
	GetUserByString(email string) (User, error)
	// Add other business logic methods...
}
type defaultUserService struct {
	db *database.Queries
}

type UsersHandler struct {
	us                 UserService
	jwtSecret          string
	minPasswordEntropy float64
}

func NewUserHandler(db *database.Queries, jwtSecret string, minPasswordEntropy float64) *UsersHandler {
	us := &defaultUserService{
		db: db,
	}
	return &UsersHandler{
		us:                 us,
		jwtSecret:          jwtSecret,
		minPasswordEntropy: minPasswordEntropy,
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
