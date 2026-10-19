package gatehost

import "testing"

func TestCanonicalHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"ExAmPlE.com", "example.com"},
		{"example.com.", "example.com"},
		{"Example.COM.", "example.com"},
		{"example.com:443", "example.com"},
		{"example.com:80", "example.com"},
		{"ExAmPlE.com:8080", "example.com"},
		{"Example.COM.:443", "example.com"},
		{" example.com ", "example.com"},
		{"example.com:99999", "example.com:99999"}, // not a valid TCP port — leave intact
		{"", ""},
		{"   ", ""},
		{"[::1]:443", "::1"},
		{"127.0.0.1:8080", "127.0.0.1"},
	}
	for _, tc := range cases {
		if got := CanonicalHost(tc.in); got != tc.want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalHostIdempotent(t *testing.T) {
	in := "ExAmPlE.com.:443"
	once := CanonicalHost(in)
	if once != "example.com" {
		t.Fatalf("first pass = %q", once)
	}
	if twice := CanonicalHost(once); twice != once {
		t.Fatalf("second pass = %q, want %q", twice, once)
	}
}
