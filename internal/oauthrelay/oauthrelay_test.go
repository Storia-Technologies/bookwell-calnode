package oauthrelay_test

import (
	"encoding/base64"
	"testing"

	"github.com/calnode/calnode/internal/oauthrelay"
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	const base = "https://acme.hosted.example.com"
	for _, inner := range []string{
		"0123456789abcdef0123456789abcdef", // sign-in: hex
		"q83vEjRWeJA-_w==",                 // calendar: padded base64url
	} {
		s := oauthrelay.Wrap(inner, base)
		host, err := oauthrelay.TargetHost(s)
		if err != nil || host != "acme.hosted.example.com" {
			t.Fatalf("TargetHost(%q) = %q, %v", s, host, err)
		}
		got, ok := oauthrelay.Unwrap(s, base)
		if !ok || got != inner {
			t.Fatalf("Unwrap(%q) = %q, %v; want %q", s, got, ok, inner)
		}
	}
}

func TestUnwrapRejectsOtherInstance(t *testing.T) {
	s := oauthrelay.Wrap("abc", "https://other.example.com")
	if _, ok := oauthrelay.Unwrap(s, "https://acme.example.com"); ok {
		t.Fatal("state tagged for another instance was accepted")
	}
	if _, ok := oauthrelay.Unwrap("abc", "https://acme.example.com"); ok {
		t.Fatal("untagged state was accepted")
	}
	if _, ok := oauthrelay.Unwrap(oauthrelay.Tag("https://acme.example.com"), "https://acme.example.com"); ok {
		t.Fatal("tag with no inner state was accepted")
	}
}

func TestTagKeepsPort(t *testing.T) {
	host, err := oauthrelay.TargetHost(oauthrelay.Wrap("x", "http://localhost:3000"))
	if err != nil || host != "localhost:3000" {
		t.Fatalf("TargetHost = %q, %v", host, err)
	}
}

func TestTargetHostRejectsJunk(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, s := range []string{
		"",
		"nodot",
		"trailing.",
		".leading",
		"x.!!!notbase64",
		"x." + enc("evil.com/path"),
		"x." + enc("user@evil.com"),
		"x." + enc(""),
	} {
		if h, err := oauthrelay.TargetHost(s); err == nil {
			t.Errorf("TargetHost(%q) = %q; want error", s, h)
		}
	}
}
