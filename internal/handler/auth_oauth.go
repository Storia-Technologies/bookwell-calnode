package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
)

// newOAuthState generates a CSRF state token, sets it as a short-lived cookie, and
// returns it for inclusion in the provider's authorize URL. Shared by the Google
// and Microsoft sign-in flows.
func (h *Handler) newOAuthState(w http.ResponseWriter) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly/SameSite/Secure are all set; Secure is h.secureCookie (dynamic on BASE_URL scheme), which gosec's static check can't verify
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   int(stateDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookie,
	})
	// The cookie keeps the bare token; only the value sent to the provider carries the
	// relay routing tag (relay mode only).
	return h.tagOAuthState(state), nil
}

// verifyOAuthState checks the ?state param against the state cookie and clears the
// cookie regardless (single use). Returns true when they match. In relay mode the
// param must also carry this instance's routing tag, which is stripped before the
// comparison.
func (h *Handler) verifyOAuthState(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(stateCookieName)
	state, tagOK := h.untagOAuthState(r.URL.Query().Get("state"))
	ok := err == nil && tagOK && c.Value != "" && state == c.Value
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly/SameSite/Secure are all set; Secure is h.secureCookie (dynamic on BASE_URL scheme), which gosec's static check can't verify
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookie,
	})
	return ok
}

// finishOAuthLogin resolves an OAuth-verified email to an existing, non-archived
// user and starts a session, redirecting to /admin on success or /admin/login with
// an error otherwise. Self-registration is not allowed — only known emails sign in.
func (h *Handler) finishOAuthLogin(w http.ResponseWriter, r *http.Request, email string) {
	var userID string
	var archivedAt sql.NullString
	if err := h.db.QueryRowContext(r.Context(),
		`SELECT id, archived_at FROM users WHERE email = ?`, email).Scan(&userID, &archivedAt); err != nil {
		h.logger.WarnContext(r.Context(), "auth: no account for email", "email", email)
		http.Redirect(w, r, "/admin/login?error=no_account", http.StatusFound)
		return
	}
	if archivedAt.Valid {
		http.Redirect(w, r, "/admin/login?error=archived", http.StatusFound)
		return
	}
	if err := h.createSession(r.Context(), w, userID); err != nil {
		h.logger.ErrorContext(r.Context(), "auth: create session", "error", err)
		http.Redirect(w, r, "/admin/login?error=session", http.StatusFound)
		return
	}
	// If this login was initiated by an MCP "Connect" flow, return to /oauth/authorize
	// (the consent step) rather than the admin home.
	if dest, ok := h.consumeOAuthReturn(w, r); ok {
		http.Redirect(w, r, dest, http.StatusFound) // #nosec G710 -- dest is validated by safeLocalPath (only "/oauth/authorize", never "//") both when set and when consumed; gosec's taint analysis can't trace through that check
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}
