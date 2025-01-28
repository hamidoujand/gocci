package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateToken(username string, jwtKey string) (string, error) {
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return str, nil
}

func ValidateToken(tokenString string, jwtKey string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims := token.Claims.(*Claims)
	return claims, nil
}
