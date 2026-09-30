package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calnode/calnode/internal/handler"
	"github.com/calnode/calnode/internal/oauthrelay"
)

// OAuth relay mode (OAUTH_CALLBACK_BASE_URL): redirect URIs point at the relay, the
// state carries a routing tag for this instance's host, and each callback strips the
// tag and still runs its full CSRF check.

const (
	relayInstanceBase = "https://acme.hosted.example.test"
	relayBase         = "https://oauth.example.test"
)

// authorizeParams parses the provider authorize URL a login/connect handler redirected to.
func authorizeParams(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302 — %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return u.Query()
}

func stateCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "calnode_oauth_state" {
			return c
		}
	}
	t.Fatal("calnode_oauth_state cookie not set")
	return nil
}

// googleCallback replays the provider's redirect to /v1/auth/callback. error=access_denied
// makes the handler stop right after the state check, so no token exchange is attempted:
// ?error=denied means the state was accepted, ?error=state that it was refused.
func googleCallback(h *handler.Handler, state string, cookie *http.Cookie) string {
	req := httptest.NewRequest(http.MethodGet,
		"/v1/auth/callback?error=access_denied&state="+url.QueryEscape(state), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.CallbackGoogle(rec, req)
	return rec.Header().Get("Location")
}

func TestOAuthRelayOff_signInStateAndRedirectUnchanged(t *testing.T) {
	h, _, _ := authTestSetup(t)
	h.SetBaseURL(relayInstanceBase)
	h.SetGoogleAuth("client-id", "client-secret", h.OAuthRedirectBase()+"/v1/auth/callback", false)

	rec := httptest.NewRecorder()
	h.LoginGoogle(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil))
	q := authorizeParams(t, rec)

	if got := q.Get("redirect_uri"); got != relayInstanceBase+"/v1/auth/callback" {
		t.Errorf("redirect_uri = %q; want the instance's own callback", got)
	}
	cookie := stateCookieFrom(t, rec)
	if q.Get("state") != cookie.Value || strings.Contains(q.Get("state"), oauthrelay.Sep) {
		t.Errorf("state = %q, cookie = %q; want the bare cookie token", q.Get("state"), cookie.Value)
	}
	if loc := googleCallback(h, q.Get("state"), cookie); loc != "/admin/login?error=denied" {
		t.Errorf("callback Location = %q; want state accepted", loc)
	}
}

func TestOAuthRelay_googleSignIn(t *testing.T) {
	h, _, _ := authTestSetup(t)
	h.SetBaseURL(relayInstanceBase)
	h.SetOAuthCallbackBaseURL(relayBase)
	h.SetGoogleAuth("client-id", "client-secret", h.OAuthRedirectBase()+"/v1/auth/callback", false)

	rec := httptest.NewRecorder()
	h.LoginGoogle(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil))
	q := authorizeParams(t, rec)
	cookie := stateCookieFrom(t, rec)
	state := q.Get("state")

	if got := q.Get("redirect_uri"); got != relayBase+"/v1/auth/callback" {
		t.Errorf("redirect_uri = %q; want the relay callback", got)
	}
	if state != cookie.Value+oauthrelay.Tag(relayInstanceBase) {
		t.Errorf("state = %q; want cookie token %q plus this instance's tag", state, cookie.Value)
	}
	if host, err := oauthrelay.TargetHost(state); err != nil || host != "acme.hosted.example.test" {
		t.Errorf("TargetHost(state) = %q, %v; want acme.hosted.example.test", host, err)
	}

	if loc := googleCallback(h, state, cookie); loc != "/admin/login?error=denied" {
		t.Errorf("tagged state: Location = %q; want it accepted (error=denied)", loc)
	}
	// The bare token (tag stripped by someone) is refused in relay mode.
	if loc := googleCallback(h, cookie.Value, cookie); loc != "/admin/login?error=state" {
		t.Errorf("untagged state: Location = %q; want error=state", loc)
	}
	// A tag naming another instance is refused even with the right token.
	other := cookie.Value + oauthrelay.Tag("https://other.hosted.example.test")
	if loc := googleCallback(h, other, cookie); loc != "/admin/login?error=state" {
		t.Errorf("foreign tag: Location = %q; want error=state", loc)
	}
	// The tag does not replace the cookie check.
	forged := "0000" + oauthrelay.Tag(relayInstanceBase)
	if loc := googleCallback(h, forged, cookie); loc != "/admin/login?error=state" {
		t.Errorf("wrong token: Location = %q; want error=state", loc)
	}
}

func TestOAuthRelay_microsoftSignIn(t *testing.T) {
	h, _, _ := authTestSetup(t)
	h.SetBaseURL(relayInstanceBase)
	h.SetOAuthCallbackBaseURL(relayBase)
	h.SetMicrosoftAuth("ms-client", "ms-secret", "common", h.OAuthRedirectBase()+"/v1/auth/microsoft/callback", false)

	rec := httptest.NewRecorder()
	h.LoginMicrosoft(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/microsoft/login", nil))
	q := authorizeParams(t, rec)
	cookie := stateCookieFrom(t, rec)

	if got := q.Get("redirect_uri"); got != relayBase+"/v1/auth/microsoft/callback" {
		t.Errorf("redirect_uri = %q; want the relay callback", got)
	}
	callback := func(state string) string {
		req := httptest.NewRequest(http.MethodGet,
			"/v1/auth/microsoft/callback?error=access_denied&state="+url.QueryEscape(state), nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.CallbackMicrosoft(rec, req)
		return rec.Header().Get("Location")
	}
	if loc := callback(q.Get("state")); loc != "/admin/login?error=denied" {
		t.Errorf("tagged state: Location = %q; want it accepted", loc)
	}
	if loc := callback(cookie.Value); loc != "/admin/login?error=state" {
		t.Errorf("untagged state: Location = %q; want error=state", loc)
	}
}

// calendarCallbackBody replays /v1/calendar/callback without a code: "missing code"
// means the state passed, "invalid or missing state" that it was refused.
func calendarCallbackBody(h *handler.Handler, state string) string {
	req := httptest.NewRequest(http.MethodGet, "/v1/calendar/callback?state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()
	h.CalendarCallback(rec, req)
	return rec.Body.String()
}

func TestOAuthRelay_calendarConnect(t *testing.T) {
	h, gc, apiKey, userID := newHandlerWithGCal(t)
	h.SetBaseURL(relayInstanceBase)
	h.SetOAuthCallbackBaseURL(relayBase)

	rec := httptest.NewRecorder()
	h.RequireAuth(h.ConnectCalendar)(rec, authReq(http.MethodGet, "/v1/calendar/connect", "", apiKey))
	state := authorizeParams(t, rec).Get("state")

	if host, err := oauthrelay.TargetHost(state); err != nil || host != "acme.hosted.example.test" {
		t.Fatalf("TargetHost(%q) = %q, %v", state, host, err)
	}
	if body := calendarCallbackBody(h, state); !strings.Contains(body, "missing code") {
		t.Errorf("tagged state refused: %s", body)
	}

	bare, err := gc.EncryptState(userID)
	if err != nil {
		t.Fatalf("EncryptState: %v", err)
	}
	if body := calendarCallbackBody(h, bare); !strings.Contains(body, "invalid or missing state") {
		t.Errorf("untagged state accepted in relay mode: %s", body)
	}
	if body := calendarCallbackBody(h, bare+oauthrelay.Tag("https://other.example.test")); !strings.Contains(body, "invalid or missing state") {
		t.Errorf("foreign tag accepted: %s", body)
	}
	// A correct tag on a state that does not decrypt is still refused.
	if body := calendarCallbackBody(h, "AAAAAAAAAAAAAAAAAAAAAAAA"+oauthrelay.Tag(relayInstanceBase)); !strings.Contains(body, "invalid or missing state") {
		t.Errorf("undecryptable state accepted: %s", body)
	}
}

func TestOAuthRelayOff_calendarStateUntagged(t *testing.T) {
	h, _, apiKey, _ := newHandlerWithGCal(t)
	h.SetBaseURL(relayInstanceBase)

	rec := httptest.NewRecorder()
	h.RequireAuth(h.ConnectCalendar)(rec, authReq(http.MethodGet, "/v1/calendar/connect", "", apiKey))
	state := authorizeParams(t, rec).Get("state")
	if strings.Contains(state, oauthrelay.Sep) {
		t.Errorf("state %q carries a routing tag with relay mode off", state)
	}
	if body := calendarCallbackBody(h, state); !strings.Contains(body, "missing code") {
		t.Errorf("state refused: %s", body)
	}
}

func TestOAuthRelay_googleSettings(t *testing.T) {
	h, _, key := newGoogleHandler(t)

	// Off: the response has no relay field.
	var resp map[string]any
	json.Unmarshal(getGoogleSettings(t, h, key).Body.Bytes(), &resp) //nolint:errcheck
	if _, ok := resp["oauth_callback_base_url"]; ok {
		t.Errorf("oauth_callback_base_url present with relay mode off: %v", resp)
	}

	h.SetOAuthCallbackBaseURL(relayBase)
	resp = nil
	json.Unmarshal(getGoogleSettings(t, h, key).Body.Bytes(), &resp) //nolint:errcheck
	if resp["oauth_callback_base_url"] != relayBase {
		t.Errorf("oauth_callback_base_url = %v; want %s", resp["oauth_callback_base_url"], relayBase)
	}
	if resp["base_url"] != "http://localhost:3000" {
		t.Errorf("base_url = %v; want the instance's own BASE_URL", resp["base_url"])
	}

	// Saving credentials hot-reloads both clients with relay redirect URIs.
	if rec := patchGoogleSettings(t, h, `{"client_id":"cid","client_secret":"sec"}`, key); rec.Code != http.StatusOK {
		t.Fatalf("patch: %d — %s", rec.Code, rec.Body.String())
	}
	rec := httptest.NewRecorder()
	h.LoginGoogle(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil))
	if got := authorizeParams(t, rec).Get("redirect_uri"); got != relayBase+"/v1/auth/callback" {
		t.Errorf("sign-in redirect_uri = %q; want relay", got)
	}
	rec = httptest.NewRecorder()
	h.RequireAuth(h.ConnectCalendar)(rec, authReq(http.MethodGet, "/v1/calendar/connect", "", key))
	if got := authorizeParams(t, rec).Get("redirect_uri"); got != relayBase+"/v1/calendar/callback" {
		t.Errorf("calendar redirect_uri = %q; want relay", got)
	}
}

// A relay base with a path prefix is used verbatim in front of the usual paths, for both
// the Settings-configured (hot-reloaded) clients and what the settings page is told.
func TestOAuthRelay_pathPrefix(t *testing.T) {
	const prefixed = "https://api.example.test/oauth/bookings"
	h, _, key := newGoogleHandler(t)
	h.SetOAuthCallbackBaseURL(prefixed)

	if rec := patchGoogleSettings(t, h, `{"client_id":"cid","client_secret":"sec"}`, key); rec.Code != http.StatusOK {
		t.Fatalf("patch: %d — %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(getGoogleSettings(t, h, key).Body.Bytes(), &resp) //nolint:errcheck
	if resp["oauth_callback_base_url"] != prefixed {
		t.Errorf("oauth_callback_base_url = %v; want %s", resp["oauth_callback_base_url"], prefixed)
	}

	rec := httptest.NewRecorder()
	h.LoginGoogle(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil))
	if got := authorizeParams(t, rec).Get("redirect_uri"); got != prefixed+"/v1/auth/callback" {
		t.Errorf("sign-in redirect_uri = %q; want %s/v1/auth/callback", got, prefixed)
	}
	rec = httptest.NewRecorder()
	h.RequireAuth(h.ConnectCalendar)(rec, authReq(http.MethodGet, "/v1/calendar/connect", "", key))
	if got := authorizeParams(t, rec).Get("redirect_uri"); got != prefixed+"/v1/calendar/callback" {
		t.Errorf("calendar redirect_uri = %q; want %s/v1/calendar/callback", got, prefixed)
	}
}
