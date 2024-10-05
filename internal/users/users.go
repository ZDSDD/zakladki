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

type UsersHandler struct {
	db                 *database.Queries
	jwtSecret          string
	minPasswordEntropy float64
}

func NewUserHandler(db *database.Queries, jwtSecret string, minPasswordEntropy float64) *UsersHandler {
	return &UsersHandler{
		db:                 db,
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
		return userReq, fmt.Errorf("Email is required")
	}
	if userReq.Password == "" {
		return userReq, fmt.Errorf("Password is required")
	}
	if userReq.Name == "" {
		return userReq, fmt.Errorf("Name is required")
	}
	return userReq, nil
}
func (uh *UsersHandler) UsersRouter() http.Handler {
	// User-related routes
	r := chi.NewRouter()

	r.Post("/", uh.handleCreateUser)
	r.Post("/login", uh.handleLogin)

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

type UserResponseLogin struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Name         string    `json:"name"`
}

func mapToJson(du *database.User, token string) UserResponseLogin {
	return UserResponseLogin{
		ID:        du.ID,
		Email:     du.Email,
		CreatedAt: du.CreatedAt,
		UpdatedAt: du.UpdatedAt,
		Token:     token,
		Name:      du.Name,
	}
}
