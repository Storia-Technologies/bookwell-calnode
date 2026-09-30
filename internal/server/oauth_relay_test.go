package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calnode/calnode/internal/config"
	"github.com/calnode/calnode/internal/db"
	"github.com/calnode/calnode/internal/handler"
)

// Env-configured Google and Microsoft clients build every redirect_uri from
// OAUTH_CALLBACK_BASE_URL (origin or origin + path prefix) when it is set, and from
// BASE_URL otherwise. Checked on the redirect_uri in each Location header.
func TestBuildHandler_oauthRedirectBase(t *testing.T) {
	const instance = "https://acme.hosted.example.test"
	for _, tc := range []struct {
		name, callbackBase, want string
	}{
		{"unset", "", instance},
		{"relay", "https://oauth.example.test", "https://oauth.example.test"},
		{"relay with path prefix", "https://api.example.test/oauth/bookings", "https://api.example.test/oauth/bookings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database, err := db.Open("sqlite://:memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			if err := db.Migrate(database); err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			handler.New(database, slog.Default()).Setup(rec, httptest.NewRequest(http.MethodPost, "/v1/setup",
				strings.NewReader(`{"name":"Host","email":"host@example.com","timezone":"UTC"}`)))
			if rec.Code != http.StatusCreated {
				t.Fatalf("setup: %d %s", rec.Code, rec.Body)
			}
			var identity struct {
				APIKey string `json:"api_key"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &identity); err != nil {
				t.Fatal(err)
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			ctx, cancel := context.WithCancel(t.Context())
			h, drain := BuildHandler(ctx, &config.Config{
				BaseURL: instance, OAuthCallbackBaseURL: tc.callbackBase, DataDir: t.TempDir(),
				// A valid 32-byte hex key: the calendar providers refuse to build without one.
				EncryptionKey:  strings.Repeat("ab", 32),
				GoogleClientID: "g-id", GoogleClientSecret: "g-secret",
				MicrosoftClientID: "m-id", MicrosoftClientSecret: "m-secret", MicrosoftTenant: "common",
			}, database, logger)
			defer func() { cancel(); drain() }()

			redirectURI := func(fn http.HandlerFunc, path string, auth bool) string {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, path, nil)
				if auth {
					req.Header.Set("Authorization", "Bearer "+identity.APIKey)
					fn = h.RequireAuth(fn)
				}
				rec := httptest.NewRecorder()
				fn(rec, req)
				if rec.Code != http.StatusFound {
					t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
				}
				u, err := url.Parse(rec.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				return u.Query().Get("redirect_uri")
			}
			for _, c := range []struct {
				fn   http.HandlerFunc
				path string
				auth bool
				want string
			}{
				{h.LoginGoogle, "/v1/auth/login", false, tc.want + "/v1/auth/callback"},
				{h.LoginMicrosoft, "/v1/auth/microsoft/login", false, tc.want + "/v1/auth/microsoft/callback"},
				{h.ConnectCalendar, "/v1/calendar/connect?provider=google", true, tc.want + "/v1/calendar/callback"},
				{h.ConnectCalendar, "/v1/calendar/connect?provider=microsoft", true, tc.want + "/v1/calendar/callback"},
			} {
				if got := redirectURI(c.fn, c.path, c.auth); got != c.want {
					t.Errorf("%s: redirect_uri = %q; want %q", c.path, got, c.want)
				}
			}
		})
	}
}
