// Package oauthrelay implements the routing tag Calnode appends to OAuth state when
// OAUTH_CALLBACK_BASE_URL is set.
//
// In relay mode every Google/Microsoft redirect_uri points at a shared relay host
// instead of this instance's BASE_URL, so one OAuth client can serve many instances.
// The relay has to know which instance a callback belongs to. It learns that from the
// state parameter: the instance appends "." + base64url(host of BASE_URL) to its
// ordinary state value, the relay decodes the last segment and 302s the browser to
// https://<host>/v1/...?<same query> (its own path prefix, if any, removed), and the
// instance then runs its usual CSRF check on the full value.
//
// The tag is routing information, not a credential. The part before it is exactly the
// state Calnode would have sent without a relay (a cookie-bound random token for
// sign-in, an encrypted blob for calendar connect), and the instance still validates
// that in full, so a relay or an attacker who rewrites the tag can at worst send a
// callback to an instance that will reject it.
package oauthrelay

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// Sep separates the instance's own state from the routing tag. Neither state form
// Calnode produces (hex, base64url) can contain it, so the last Sep is unambiguous.
const Sep = "."

// Tag returns the routing tag for an instance whose identity host is baseURL:
// Sep + unpadded base64url(host[:port]). It returns "" when baseURL has no host.
func Tag(baseURL string) string {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return Sep + base64.RawURLEncoding.EncodeToString([]byte(strings.ToLower(u.Host)))
}

// Wrap appends baseURL's routing tag to state.
func Wrap(state, baseURL string) string {
	return state + Tag(baseURL)
}

// Unwrap strips baseURL's routing tag from state. ok is false when the tag is missing
// or names a different instance, in which case the callback must be rejected.
func Unwrap(state, baseURL string) (inner string, ok bool) {
	tag := Tag(baseURL)
	if tag == "" || !strings.HasSuffix(state, tag) {
		return "", false
	}
	inner = strings.TrimSuffix(state, tag)
	return inner, inner != ""
}

// ErrNoTag is returned by TargetHost when state carries no routing tag.
var ErrNoTag = errors.New("oauthrelay: state has no routing tag")

// TargetHost decodes the instance host (host[:port]) from a tagged state. It is what
// a relay implementation calls; Calnode itself never needs it. The result is only
// syntactically checked: a relay must still match it against the hosts it serves
// before redirecting, or it is an open redirect.
func TargetHost(state string) (string, error) {
	i := strings.LastIndex(state, Sep)
	if i <= 0 || i == len(state)-1 {
		return "", ErrNoTag
	}
	b, err := base64.RawURLEncoding.DecodeString(state[i+1:])
	if err != nil {
		return "", ErrNoTag
	}
	host := string(b)
	if u, err := url.Parse("https://" + host); err != nil || u.Host != host || host == "" {
		return "", ErrNoTag
	}
	return host, nil
}
