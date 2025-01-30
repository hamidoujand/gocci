package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// GenerateToken generates the jwt token.
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

// ValidateToken validate the given jwt token against the given secret key and returns the parsed claims.
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

// RegisterUser registers a user into redis.
func RegisterUser(ctx context.Context, redis *redis.Client, username string, password string) error {
	if exists := redis.SIsMember(ctx, "users", username).Val(); exists {
		return fmt.Errorf("username %q, already taken", username)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generate from password: %w", err)
	}

	if err := redis.HSet(ctx, "user_credentials", username, hash).Err(); err != nil {
		return fmt.Errorf("storing credentials: %w", err)
	}

	if err := redis.SAdd(ctx, "users", username).Err(); err != nil {
		return fmt.Errorf("sAdd: %w", err)
	}

	return nil
}

// Login validates user and password against the hash password.
func Login(ctx context.Context, redis *redis.Client, username string, password string) error {
	hash, err := redis.HGet(ctx, "user_credentials", username).Bytes()
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}

// DeleteUserCredentials deletes a user when the user left the chat.
func DeletUserCredentials(ctx context.Context, redis *redis.Client, username string) error {
	if err := redis.HDel(ctx, "user_credentials", username).Err(); err != nil {
		return fmt.Errorf("user not found")
	}

	if err := redis.SRem(ctx, "users", username).Err(); err != nil {
		return fmt.Errorf("user not found")
	}
	return nil
}
