package auth

import (
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
)

type HashedPassword string

func (hp HashedPassword) ToString() string {
	return string(hp)
}

func HashPassword(password string) (HashedPassword, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return HashedPassword(hash), err
}

func CheckPasswordHash(password string, hash HashedPassword) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func CheckPasswordStrength(password string, minPasswordEntropy float64) error {
	return passwordvalidator.Validate(password, minPasswordEntropy)
}
