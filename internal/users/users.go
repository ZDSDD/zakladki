package users

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/zdsdd/zakladki/internal/auth"
	"github.com/zdsdd/zakladki/internal/database"
	"github.com/zdsdd/zakladki/internal/jsonUtils"
)

type UserService struct {
	db                 *database.Queries
	jwtSecret          string
	minPasswordEntropy float64
}

func NewUserService(db *database.Queries, jwtSecret string, minPasswordEntropy float64) *UserService {
	return &UserService{
		db:                 db,
		jwtSecret:          jwtSecret,
		minPasswordEntropy: minPasswordEntropy,
	}
}

func (us *UserService) UsersRouter() http.Handler {
	// User-related routes
	r := chi.NewRouter()

	r.Post("/", us.requireLoginAndPassword(us.handleCreateUser))
	r.Post("/login", us.requireLoginAndPassword(us.handleLogin))

	// mux.HandleFunc("PUT /api/users", us.requireBearerToken(us.handleUpdateUser))
	r.Put("/password", us.requireValidJWTToken(us.handleUpdatePassword))
	r.Put("/email", us.requireValidJWTToken(us.handleUpdateEmail))

	// JWT-related routers
	r.Post("/refresh", us.requireValidJWTToken(us.handleRefreshToken))
	r.Post("/revoke", us.requireBearerToken(us.handleRevokeToken))
	return r
}

func (us *UserService) handleLogin(w http.ResponseWriter, r *http.Request, email, password string) {
	user, err := us.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	if err := auth.CheckPasswordHash(password, user.HashedPassword); err != nil {
		jsonUtils.ResponseWithJsonError(w, "Invalid password", 401)
		return
	}

	token, err := auth.MakeJWT(user.ID, us.jwtSecret, time.Hour)

	var refreshToken database.RefreshToken
	_, err = us.db.GetRefreshTokenForUser(r.Context(), user.ID)
	if err == nil { //There is already refresh token for this user in the database.
		refreshToken, err = us.db.UpdateExpiresAtRefreshToken(r.Context(), database.UpdateExpiresAtRefreshTokenParams{
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
		refreshToken, err = us.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshTokenID,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
	}
	jsonUtils.ResponseWithJson(mapToJson(&user, token, refreshToken.Token), w, http.StatusOK)
}

func (us *UserService) requireLoginAndPassword(next func(w http.ResponseWriter, r *http.Request, email, password string)) http.HandlerFunc {
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

func (us *UserService) handleRefreshToken(w http.ResponseWriter, r *http.Request, refreshToken string, user *database.User) {
	rtdb, err := us.db.GetRefreshToken(r.Context(), refreshToken)
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
	token, err := auth.MakeJWT(user.ID, us.jwtSecret, time.Hour)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	jsonUtils.ResponseWithJson(map[string]string{"token": token}, w, http.StatusOK)
}

func (us *UserService) requireBearerToken(next func(w http.ResponseWriter, r *http.Request, token string)) http.HandlerFunc {
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
		next(w, r, token)
	}
}

// RequireBearerToken wrapper with JWT token validation
func (us *UserService) requireValidJWTToken(next func(w http.ResponseWriter, r *http.Request, token string, user *database.User)) http.HandlerFunc {
	return us.requireBearerToken(func(w http.ResponseWriter, r *http.Request, token string) {
		userId, err := auth.ValidateJWT(token, us.jwtSecret) // Validate JWT token
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Retrieve user from database using the userId extracted from the token
		user, err := us.db.GetUserById(r.Context(), userId)
		if err != nil {
			jsonUtils.ResponseWithJsonError(w, "User not found", http.StatusUnauthorized)
			return
		}
		// Call the next function with token and user
		next(w, r, token, &user)
	})
}
func (us *UserService) handleRevokeToken(w http.ResponseWriter, r *http.Request, refreshToken string) {
	err := us.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}
func (us *UserService) handleCreateUser(w http.ResponseWriter, r *http.Request, email, password string) {

	_, err := us.db.GetUserByEmail(r.Context(), email)
	if err == nil {
		jsonUtils.ResponseWithJsonError(w, "User already exists", 400)
		return
	}
	if !auth.IsEmailValid(email) {
		jsonUtils.ResponseWithJsonError(w, "Invalid email", 400)
		return
	}
	if err := auth.CheckPasswordStrength(password, us.minPasswordEntropy); err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 400)
		return
	}
	hashedPasswd, err := auth.HashPassword(password)

	user, err := us.db.CreateUser(r.Context(), database.CreateUserParams{
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

func (us *UserService) handleUpdateEmail(w http.ResponseWriter, r *http.Request, token string, user *database.User) {
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
	updatedUser, err := us.db.UpdateUserEmail(r.Context(), database.UpdateUserEmailParams{
		Email: userReq.Email,
		ID:    user.ID,
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

func (us *UserService) handleUpdatePassword(w http.ResponseWriter, r *http.Request, token string, user *database.User) {
	type UserReqBody struct {
		Password string `json:"password"`
	}
	var userReq UserReqBody
	json.NewDecoder(r.Body).Decode(&userReq)
	if userReq.Password == "" {
		jsonUtils.ResponseWithJsonError(w, "password is required", 400)
		return
	}
	if err := auth.CheckPasswordStrength(userReq.Password, us.minPasswordEntropy); err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 400)
		return
	}

	hashesPassword, err := auth.HashPassword(userReq.Password)
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	updatedUser, err := us.db.UpdateUserPassword(r.Context(), database.UpdateUserPasswordParams{
		HashedPassword: hashesPassword,
		ID:             user.ID,
	})
	if err != nil {
		jsonUtils.ResponseWithJsonError(w, err.Error(), 500)
		return
	}

	jsonUtils.ResponseWithJson(mapToJson(&updatedUser, "", ""), w, 201)
}
