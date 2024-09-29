package users

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
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

func (uh *UsersHandler) UsersRouter() http.Handler {
	// User-related routes
	r := chi.NewRouter()

	r.Post("/", uh.requireLoginAndPassword(uh.handleCreateUser))
	r.Post("/login", uh.requireLoginAndPassword(uh.handleLogin))

	// mux.HandleFunc("PUT /api/users", uh.requireBearerToken(uh.handleUpdateUser))
	r.Put("/password", uh.RequireValidJWTToken(http.HandlerFunc(uh.handleUpdatePassword)))
	r.Put("/email", uh.RequireValidJWTToken(http.HandlerFunc(uh.handleUpdateEmail)))

	// JWT-related routers
	r.Post("/refresh", uh.RequireValidJWTToken(http.HandlerFunc(uh.handleRefreshToken)))
	r.Post("/revoke", uh.requireBearerToken(http.HandlerFunc(uh.handleRevokeToken)))
	return r
}

func (uh *UsersHandler) handleLogin(w http.ResponseWriter, r *http.Request, email, password string) {
	user, err := uh.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	if err := auth.CheckPasswordHash(password, user.HashedPassword); err != nil {
		jsonUtils.ResponseWithJsonError(w, "Invalid password", 401)
		return
	}

	token, err := auth.MakeJWT(user.ID, uh.jwtSecret, time.Hour)

	var refreshToken database.RefreshToken
	_, err = uh.db.GetRefreshTokenForUser(r.Context(), user.ID)
	if err == nil { //There is already refresh token for this user in the database.
		refreshToken, err = uh.db.UpdateExpiresAtRefreshToken(r.Context(), database.UpdateExpiresAtRefreshTokenParams{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
			UserID:    user.ID,
		})
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
			return
		}

	} else {
		refreshTokenID, err := auth.MakeRefreshToken()
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
			return
		}
		refreshToken, err = uh.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshTokenID,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
	}
	jsonUtils.ResponseWithJson(mapToJson(&user, token, refreshToken.Token), w, http.StatusOK)
}

func (uh *UsersHandler) requireLoginAndPassword(next func(w http.ResponseWriter, r *http.Request, email, password string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type UserReqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		var userReq UserReqBody
		json.NewDecoder(r.Body).Decode(&userReq)
		if userReq.Email == "" {
			jsonUtils.ResponseWithJsonError(w, "Email is required", 400)
			return
		}
		if userReq.Password == "" {
			jsonUtils.ResponseWithJsonError(w, "Password is required", 400)
			return
		}
		next(w, r, userReq.Email, userReq.Password)
	}
}

func (uh *UsersHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := GetBearerToken(r)
	rtdb, err := uh.db.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 401)
		return
	}
	if rtdb.ExpiresAt.Before(time.Now()) {
		jsonUtils.ResponseWithJsonError(w, "Refresh token expired", 401)
		return
	}
	if rtdb.RevokedAt.Valid {
		jsonUtils.ResponseWithJsonError(w, "Refresh token revoked", 401)
		return
	}
	userId, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 401)
		return
	}
	if rtdb.UserID != userId {
		jsonUtils.ResponseWithJsonError(w, "Refresh token does not belong to the user", 401)
		return
	}
	token, err := auth.MakeJWT(userId, uh.jwtSecret, time.Hour)

	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(map[string]string{"token": token}, w, http.StatusOK)
}

type contextKey string

const TokenKey contextKey = "auth.token"
const UserIDKey contextKey = "auth.userId"

func (uh *UsersHandler) requireBearerToken(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), 401)
			return
		}
		if token == "" {
			jsonUtils.ResponseWithJsonError(w, "bearer token is required", 400)
			return
		}
		ctx := context.WithValue(r.Context(), TokenKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

const PermissionsKey contextKey = "acl.permission"
const RoleKey contextKey = "acl.role"

func (uh *UsersHandler) RequireValidJWTToken(next http.Handler) http.HandlerFunc {
	return uh.requireBearerToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)
		if err != nil {
			log.Printf("Error getting bearer token: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		userId, err := auth.ValidateJWT(token, uh.jwtSecret)
		if err != nil {
			log.Printf("Error validating JWT: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := uh.db.GetUserById(r.Context(), userId)
		if err != nil {
			log.Printf("Error getting user: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, userId)
		ctx = context.WithValue(ctx, RoleKey, Role(user.Role))

		next.ServeHTTP(w, r.WithContext(ctx))
	}))
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
func GetBearerToken(r *http.Request) (string, error) {
	userId, ok := r.Context().Value(TokenKey).(string)
	if !ok || userId == "" {
		return "", fmt.Errorf("JWT Token not found in context")
	}
	return userId, nil
}

func (uh *UsersHandler) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := GetBearerToken(r)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 401)
		return
	}
	if err = uh.db.RevokeRefreshToken(r.Context(), refreshToken); err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}

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

type UserResponseLogin struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
}

func mapToJson(du *database.User, token string, refreshToken string) UserResponseLogin {
	return UserResponseLogin{
		ID:           du.ID,
		Email:        du.Email,
		CreatedAt:    du.CreatedAt,
		UpdatedAt:    du.UpdatedAt,
		Token:        token,
		RefreshToken: refreshToken,
	}
}

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

func (uh *UsersHandler) RequirePermission(requiredPermission Permissions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userRole, ok := ctx.Value(RoleKey).(Role)
			if !ok || !userRole.HasPermission(requiredPermission) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (uh *UsersHandler) AdminOnly(next http.Handler) http.Handler {
	return uh.RequireValidJWTToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		role, ok := ctx.Value(RoleKey).(Role)
		if !ok {
			log.Printf("Role not found in context")
			log.Printf("Context: %v", ctx)
			log.Printf("Role key: %v", RoleKey)
			log.Printf("Role: %v", role)
			log.Printf("Role value: %v", ctx.Value(RoleKey))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("User role: %v", role)
		if !role.HasPermission(CanView | CanEdit | CanDelete | CanCreate) {
			log.Printf("User is not an admin (role: %v)", role)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}
