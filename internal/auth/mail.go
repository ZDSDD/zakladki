package auth

import "net/mail"

// Keep in min,
func IsEmailValid(email string) bool {
	emailAddress, err := mail.ParseAddress(email)
	return err == nil && emailAddress.Address == email
}
