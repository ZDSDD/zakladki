package users

import (
	"log"
	"net/http"
)

type Permissions int

const (
	CanView   Permissions = 1 << iota // 1
	CanEdit                           // 2
	CanDelete                         // 4
	CanCreate                         // 8
)

type Role int

// Define constants for each role
const (
	Viewer    Role = Role(CanView)
	Moderator      = Role(CanView | CanEdit)
	Admin          = Role(CanView | CanEdit | CanDelete | CanCreate)
)

// Check if a role is valid
func IsValidRole(role Role) bool {
	switch role {
	case Admin, Moderator, Viewer:
		return true
	}
	return false
}

// Check if a role has a specific permission
func (r Role) HasPermission(p Permissions) bool {
	return int(r)&int(p) != 0
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
