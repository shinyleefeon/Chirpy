package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "mySecurePassword123",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false,
		},
		{
			name:     "long password",
			password: "thisIsAVeryLongPasswordWithLotsOfCharacters1234567890!@#$%^&*()",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && hash == "" {
				t.Errorf("HashPassword() returned empty hash")
			}
			if !tt.wantErr && hash == tt.password {
				t.Errorf("HashPassword() returned unhashed password")
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	// Create a valid hash for testing
	password := "testPassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to create test hash: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			want:     true,
			wantErr:  false,
		},
		{
			name:     "incorrect password",
			password: "wrongPassword",
			hash:     hash,
			want:     false,
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			hash:     hash,
			want:     false,
			wantErr:  false,
		},
		{
			name:     "invalid hash format",
			password: password,
			hash:     "invalidhash",
			want:     false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckPasswordHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMakeJWT(t *testing.T) {
	testUserID := uuid.New()
	testSecret := "test-secret-key"

	tests := []struct {
		name        string
		userID      uuid.UUID
		tokenSecret string
		expiresIn   time.Duration
		wantErr     bool
	}{
		{
			name:        "valid token with 1 hour expiry",
			userID:      testUserID,
			tokenSecret: testSecret,
			expiresIn:   time.Hour,
			wantErr:     false,
		},
		{
			name:        "valid token with short expiry",
			userID:      testUserID,
			tokenSecret: testSecret,
			expiresIn:   time.Minute,
			wantErr:     false,
		},
		{
			name:        "empty secret",
			userID:      testUserID,
			tokenSecret: "",
			expiresIn:   time.Hour,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := MakeJWT(tt.userID, tt.tokenSecret, tt.expiresIn)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && token == "" {
				t.Errorf("MakeJWT() returned empty token")
			}

			// Verify token can be parsed and contains correct claims
			if !tt.wantErr {
				parsedToken, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
					return []byte(tt.tokenSecret), nil
				})
				if err != nil {
					t.Errorf("Failed to parse generated token: %v", err)
					return
				}
				if claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims); ok {
					if claims.Subject != tt.userID.String() {
						t.Errorf("Token subject = %v, want %v", claims.Subject, tt.userID.String())
					}
					if claims.Issuer != "Chirpy" {
						t.Errorf("Token issuer = %v, want Chirpy", claims.Issuer)
					}
				}
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	testUserID := uuid.New()
	testSecret := "test-secret-key"
	validToken, _ := MakeJWT(testUserID, testSecret, time.Hour)
	expiredToken, _ := MakeJWT(testUserID, testSecret, -time.Hour) // already expired

	tests := []struct {
		name        string
		tokenString string
		tokenSecret string
		wantUserID  uuid.UUID
		wantErr     bool
	}{
		{
			name:        "valid token",
			tokenString: validToken,
			tokenSecret: testSecret,
			wantUserID:  testUserID,
			wantErr:     false,
		},
		{
			name:        "expired token",
			tokenString: expiredToken,
			tokenSecret: testSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "invalid secret",
			tokenString: validToken,
			tokenSecret: "wrong-secret",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "malformed token",
			tokenString: "not.a.valid.token",
			tokenSecret: testSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "empty token",
			tokenString: "",
			tokenSecret: testSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := ValidateJWT(tt.tokenString, tt.tokenSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() userID = %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestHashPasswordAndCheck(t *testing.T) {
	// Integration test: hash a password and verify it
	password := "integrationTestPassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	match, err := CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash() failed: %v", err)
	}

	if !match {
		t.Errorf("CheckPasswordHash() returned false for correct password")
	}

	// Verify different password doesn't match
	wrongMatch, err := CheckPasswordHash("wrongPassword", hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash() failed: %v", err)
	}

	if wrongMatch {
		t.Errorf("CheckPasswordHash() returned true for incorrect password")
	}
}

func TestMakeJWTAndValidate(t *testing.T) {
	// Integration test: create and validate a JWT
	userID := uuid.New()
	secret := "integration-test-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() failed: %v", err)
	}

	gotUserID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT() failed: %v", err)
	}

	if gotUserID != userID {
		t.Errorf("ValidateJWT() returned userID = %v, want %v", gotUserID, userID)
	}
}

func TestHashPasswordUniqueness(t *testing.T) {
	// Verify that hashing the same password twice produces different hashes
	// (due to different salts)
	password := "testPassword"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("HashPassword() produced identical hashes for same password (salt not working)")
	}

	// Both hashes should still validate the password
	match1, _ := CheckPasswordHash(password, hash1)
	match2, _ := CheckPasswordHash(password, hash2)

	if !match1 || !match2 {
		t.Errorf("Unique hashes don't both validate the original password")
	}
}
