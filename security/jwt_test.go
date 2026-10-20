package security

import (
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJwt(t *testing.T) {
	SignKey = nil
	if _, err := (Jwt[string]{}).CreateToken("x", jwt.RegisteredClaims{}); err == nil {
		t.Fatal("empty key must not sign")
	}

	SignKey = []byte(strings.Repeat("k", MinKeySize))
	token, err := Jwt[string]{}.CreateToken("x", jwt.RegisteredClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := (Jwt[string]{}).DecodeToken(token); err != nil || claims.Payload != "x" {
		t.Fatalf("decode: %+v %v", claims, err)
	}

	hs512, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{}).SignedString(SignKey)
	if _, err := (Jwt[string]{}).DecodeToken(hs512); err == nil {
		t.Fatal("only HS256 is accepted")
	}
}

func TestSetSignKey(t *testing.T) {
	// SignKey is a package variable: put it back when the test ends.
	old := SignKey
	t.Cleanup(func() { SignKey = old })

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"empty", "", true},
		{"one byte short", strings.Repeat("k", MinKeySize-1), true},
		{"exactly the minimum", strings.Repeat("k", MinKeySize), false},
		{"longer than the minimum", strings.Repeat("k", MinKeySize*2), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetSignKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SetSignKey(%d bytes) error = %v, wantErr %v", len(tt.key), err, tt.wantErr)
			}
			if err == nil && string(SignKey) != tt.key {
				t.Fatalf("SignKey was not set to the given key")
			}
		})
	}

	// A key accepted by SetSignKey must be able to sign and check a token.
	if err := SetSignKey(strings.Repeat("k", MinKeySize)); err != nil {
		t.Fatal(err)
	}
	token, err := Jwt[string]{}.CreateToken("x", jwt.RegisteredClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := (Jwt[string]{}).DecodeToken(token); err != nil || claims.Payload != "x" {
		t.Fatalf("decode: %+v %v", claims, err)
	}
}

func TestErrorStatus(t *testing.T) {
	if got := ErrInvalidToken.(interface{ HTTPStatus() int }).HTTPStatus(); got != 401 {
		t.Fatalf("core.Error must reply 401 to an invalid token: %d", got)
	}
}
