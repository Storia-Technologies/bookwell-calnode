package gcal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthURL_requestsNarrowScopes(t *testing.T) {
	u, err := url.Parse(newTestClient(t).AuthURL("s"))
	if err != nil {
		t.Fatal(err)
	}
	got := u.Query().Get("scope")
	want := "https://www.googleapis.com/auth/calendar.events " +
		"https://www.googleapis.com/auth/calendar.calendarlist.readonly " +
		"https://www.googleapis.com/auth/calendar.freebusy"
	if got != want {
		t.Errorf("scope = %q; want %q", got, want)
	}
	for _, s := range strings.Fields(got) {
		if s == broadScope {
			t.Errorf("AuthURL still requests the broad %s scope", broadScope)
		}
	}
}

func TestMissingScopes(t *testing.T) {
	all := strings.Join(Scopes, " ")
	for _, tc := range []struct {
		name, granted string
		missing       int
	}{
		{"not reported", "", 0},
		{"all narrow scopes", all, 0},
		{"all narrow scopes plus others", "openid " + all + " email", 0},
		{"legacy broad scope", broadScope, 0},
		{"freebusy unticked", Scopes[0] + " " + Scopes[1], 1},
		{"only events", Scopes[0], 2},
		{"unrelated only", "openid email", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := missingScopes(tc.granted); len(got) != tc.missing {
				t.Errorf("missingScopes(%q) = %v; want %d missing", tc.granted, got, tc.missing)
			}
		})
	}
}

// fakeGoogle serves the token endpoint (reporting grantedScope) and the calendarList
// primary entry used for the account email, and records the Calendar API paths hit.
func fakeGoogle(t *testing.T, grantedScope string) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","refresh_token":"rt","expires_in":3600,"scope":%q}`, grantedScope)
		case "/users/me/calendarList/primary":
			paths = append(paths, r.URL.Path)
			fmt.Fprint(w, `{"id":"host@example.com","primary":true}`)
		default:
			paths = append(paths, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func exchangeAgainst(t *testing.T, srv *httptest.Server) (*Client, error) {
	t.Helper()
	c := newTestClient(t)
	c.apiBase = srv.URL
	c.config.Endpoint.TokenURL = srv.URL + "/token"
	seedUser(t, c.db, "user-1")
	return c, c.Exchange(context.Background(), "user-1", "code", "")
}

func accountEmail(t *testing.T, c *Client) (string, bool) {
	t.Helper()
	var email string
	err := c.db.QueryRow(`SELECT COALESCE(account_email,'') FROM calendar_connections WHERE user_id = 'user-1' AND provider = 'google'`).Scan(&email)
	if err != nil {
		return "", false
	}
	return email, true
}

func TestExchange_fullGrantSavesAccountEmailFromCalendarList(t *testing.T) {
	for _, granted := range []string{strings.Join(Scopes, " "), broadScope} {
		srv, paths := fakeGoogle(t, granted)
		c, err := exchangeAgainst(t, srv)
		if err != nil {
			t.Fatalf("Exchange(granted=%q): %v", granted, err)
		}
		if email, ok := accountEmail(t, c); !ok || email != "host@example.com" {
			t.Errorf("account_email = %q (row=%v); want host@example.com", email, ok)
		}
		if len(*paths) != 1 || (*paths)[0] != "/users/me/calendarList/primary" {
			t.Errorf("Calendar API paths = %v; want only calendarList/primary (calendars.get is outside the scopes)", *paths)
		}
	}
}

func TestExchange_partialGrantRefused(t *testing.T) {
	srv, _ := fakeGoogle(t, Scopes[0]+" "+Scopes[1]) // freebusy unticked on the consent screen
	c, err := exchangeAgainst(t, srv)
	if !errors.Is(err, ErrMissingScopes) {
		t.Fatalf("Exchange err = %v; want ErrMissingScopes", err)
	}
	if _, ok := accountEmail(t, c); ok {
		t.Error("a connection was saved despite the partial grant")
	}
}
