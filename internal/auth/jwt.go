package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type MyCustomClaims struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Subject   string `json:"sub"`
	jwt.RegisteredClaims
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := MyCustomClaims{
		Issuer:    "zakladki",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(expiresIn).Unix(),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (userId uuid.UUID, err error) {
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.UUID{}, err
	} else if claims, ok := token.Claims.(*MyCustomClaims); ok {
		userId, err = uuid.Parse(claims.Subject)
	} else {
		return uuid.UUID{}, fmt.Errorf("unknown claims type, cannot proceed")
	}
	return userId, err
}
