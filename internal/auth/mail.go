package auth

import "net/mail"

// Keep in mind, that this is a very simple email validation function.
func IsEmailValid(email string) bool {
	emailAddress, err := mail.ParseAddress(email)
	return err == nil && emailAddress.Address == email
}
