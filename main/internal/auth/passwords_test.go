package auth

import "testing"

func TestHashPassword(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %s", err)
	}
	if hash == "" {
		t.Error("Hash is empty")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %s", err)
	}
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("Error checking password hash: %s", err)
	}

	err = CheckPasswordHash("wrongpassword", hash)
	if err == nil {
		t.Error("CheckPasswordHash should return an error")
	}

	err = CheckPasswordHash(password, "wronghash")
	if err == nil {
		t.Error("CheckPasswordHash should return an error")
	}
}
