package auth

import "github.com/golang-jwt/jwt/v5"

// User represents a user in the app.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// Claims are data encoded into jwt token.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}
