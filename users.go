package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
)

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request, email, password string) {
	user, err := cfg.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	if err := auth.CheckPasswordHash(password, user.HashedPassword); err != nil {
		ResponseWithJsonError(w, "Invalid password", 401)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)

	var refreshToken database.RefreshToken
	_, err = cfg.db.GetRefreshTokenForUser(r.Context(), user.ID)
	if err == nil { //There is already refresh token for this user in the database.
		refreshToken, err = cfg.db.UpdateExpiresAtRefreshToken(r.Context(), database.UpdateExpiresAtRefreshTokenParams{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
			UserID:    user.ID,
		})
		if err != nil {
			ResponseWithJsonError(w, err.Error(), 500)
			return
		}

	} else {
		refreshTokenID, err := auth.MakeRefreshToken()
		if err != nil {
			ResponseWithJsonError(w, err.Error(), 500)
			return
		}
		refreshToken, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshTokenID,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
	}
	ResponseWithJson(mapToJson(&user, token, refreshToken.Token), w, http.StatusOK)
}

func (cfg *apiConfig) requireLoginAndPassword(next func(w http.ResponseWriter, r *http.Request, email, password string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type UserReqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		var userReq UserReqBody
		json.NewDecoder(r.Body).Decode(&userReq)
		if userReq.Email == "" {
			ResponseWithJsonError(w, "Email is required", 400)
			return
		}
		if userReq.Password == "" {
			ResponseWithJsonError(w, "Password is required", 400)
			return
		}
		next(w, r, userReq.Email, userReq.Password)
	}
}

func (cfg *apiConfig) handleRefreshToken(w http.ResponseWriter, r *http.Request, refreshToken string, user *database.User) {
	rtdb, err := cfg.db.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		ResponseWithJsonError(w, err.Error(), 401)
		return
	}
	if rtdb.ExpiresAt.Before(time.Now()) {
		ResponseWithJsonError(w, "Refresh token expired", 401)
		return
	}
	if rtdb.RevokedAt.Valid {
		ResponseWithJsonError(w, "Refresh token revoked", 401)
		return
	}
	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	ResponseWithJson(map[string]string{"token": token}, w, http.StatusOK)
}

func (cfg *apiConfig) requireBearerToken(next func(w http.ResponseWriter, r *http.Request, token string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			ResponseWithJsonError(w, err.Error(), 401)
			return
		}
		if token == "" {
			ResponseWithJsonError(w, "bearer token is required", 400)
			return
		}
		next(w, r, token)
	}
}

// RequireBearerToken wrapper with JWT token validation
func (cfg *apiConfig) requireValidJWTToken(next func(w http.ResponseWriter, r *http.Request, token string, user *database.User)) http.HandlerFunc {
	return cfg.requireBearerToken(func(w http.ResponseWriter, r *http.Request, token string) {
		userId, err := auth.ValidateJWT(token, cfg.jwtSecret) // Validate JWT token
		if err != nil {
			ResponseWithJsonError(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Retrieve user from database using the userId extracted from the token
		user, err := cfg.db.GetUserById(r.Context(), userId)
		if err != nil {
			ResponseWithJsonError(w, "User not found", http.StatusUnauthorized)
			return
		}
		// Call the next function with token and user
		next(w, r, token, &user)
	})
}
func (cfg *apiConfig) handleRevokeToken(w http.ResponseWriter, r *http.Request, refreshToken string) {
	err := cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}
func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request, email, password string) {

	_, err := cfg.db.GetUserByEmail(r.Context(), email)
	if err == nil {
		ResponseWithJsonError(w, "User already exists", 400)
		return
	}
	if !auth.IsEmailValid(email) {
		ResponseWithJsonError(w, "Invalid email", 400)
		return
	}
	if err := auth.CheckPasswordStrength(password, cfg.minPasswordEntropy); err != nil {
		ResponseWithJsonError(w, err.Error(), 400)
		return
	}
	hashedPasswd, err := auth.HashPassword(password)

	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          email,
		HashedPassword: hashedPasswd,
	})
	if err != nil {
		ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	ResponseWithJson(mapToJson(&user, "", ""), w, http.StatusCreated)
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

func (cfg *apiConfig) handleUpdateEmail(w http.ResponseWriter, r *http.Request, token string, user *database.User) {
	type UserReqBody struct {
		Email string `json:"email"`
	}
	var userReq UserReqBody
	json.NewDecoder(r.Body).Decode(&userReq)
	if userReq.Email == "" {
		ResponseWithJsonError(w, "Email is required", 400)
		return
	}
	if !auth.IsEmailValid(userReq.Email) {
		ResponseWithJsonError(w, "Invalid email", 400)
		return
	}
	updatedUser, err := cfg.db.UpdateUserEmail(r.Context(), database.UpdateUserEmailParams{
		Email: userReq.Email,
		ID:    user.ID,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			ResponseWithJsonError(w, "Email already exists", 403)
			return
		}
		ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	ResponseWithJson(mapToJson(&updatedUser, "", ""), w, 201)
}

func (cfg *apiConfig) handleUpdatePassword(w http.ResponseWriter, r *http.Request, token string, user *database.User) {
	type UserReqBody struct {
		Password string `json:"password"`
	}
	var userReq UserReqBody
	json.NewDecoder(r.Body).Decode(&userReq)
	if userReq.Password == "" {
		ResponseWithJsonError(w, "password is required", 400)
		return
	}
	if err := auth.CheckPasswordStrength(userReq.Password, cfg.minPasswordEntropy); err != nil {
		ResponseWithJsonError(w, err.Error(), 400)
		return
	}

	hashesPassword, err := auth.HashPassword(userReq.Password)
	if err != nil {
		ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	updatedUser, err := cfg.db.UpdateUserPassword(r.Context(), database.UpdateUserPasswordParams{
		HashedPassword: hashesPassword,
		ID:             user.ID,
	})
	if err != nil {
		ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	ResponseWithJson(mapToJson(&updatedUser, "", ""), w, 201)
}
