package users

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

func (uh *UsersHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	// Extract refresh token from cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		jsonUtils.RespondWithJsonError(w, "Refresh token not found", 401)
		return
	}
	refreshToken := cookie.Value

	rtdb, err := uh.us.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 401)
		return
	}
	userId, err := GetUserIDFromContext(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 401)
		return
	}
	if rtdb.UserID != userId {
		jsonUtils.RespondWithJsonError(w, "Refresh token does not belong to the user", 401)
		return
	}
	token, err := auth.MakeJWT(userId, uh.jwtSecret, time.Hour)

	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
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
			jsonUtils.RespondWithJsonError(w, err.Error(), 401)
			return
		}
		if token == "" {
			jsonUtils.RespondWithJsonError(w, "bearer token is required", 400)
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
		token, err := GetBearerTokenFromContext(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		userId, err := auth.ValidateJWT(token, uh.jwtSecret)
		if err != nil {
			log.Printf("Error validating JWT: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := uh.us.GetUserById(r.Context(), userId)
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

func (uh *UsersHandler) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := GetBearerTokenFromContext(r)
	if err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 401)
		return
	}
	if err = uh.us.RevokeRefreshToken(r.Context(), refreshToken); err != nil {
		jsonUtils.RespondWithJsonError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}
