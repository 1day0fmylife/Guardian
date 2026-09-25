package security

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify")
	}
	ok, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword wrong password: %v", err)
	}
	if ok {
		t.Fatal("wrong password unexpectedly verified")
	}
}

func TestPasswordMinimumLength(t *testing.T) {
	if _, err := HashPassword("too-short"); err == nil {
		t.Fatal("expected short password to be rejected")
	}
}
