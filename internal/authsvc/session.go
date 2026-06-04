package authsvc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sessionCookieName is the HMAC session cookie set at login and checked by
// /validate. Stateless: a Python-issued cookie validates identically here under
// the same SESSION_SECRET (cross-compatible during the migration).
const sessionCookieName = "abc_session"

// sessionVerifier signs and verifies abc_session tokens. Token shape (after
// base64url-decode): "<username>:<expiry-unix>:<hex-hmac-sha256>", matching the
// Python _make_session_token / _verify_session_token. username may itself contain
// ':' — expiry and sig are always the last two fields.
type sessionVerifier struct {
	secret []byte
}

func (v sessionVerifier) make(username string, ttl time.Duration) string {
	expiry := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s:%d", username, expiry)
	return base64.URLEncoding.EncodeToString([]byte(payload + ":" + hmacHex(v.secret, payload)))
}

// verify returns (username, true) when the token is well-formed, unexpired, and
// its signature matches.
func (v sessionVerifier) verify(token string) (string, bool) {
	if len(v.secret) == 0 || token == "" {
		return "", false
	}
	raw, err := decodeB64URL(token)
	if err != nil {
		return "", false
	}
	s := string(raw)

	// rsplit on ':' into [username, expiry, sig].
	i2 := strings.LastIndexByte(s, ':')
	if i2 < 0 {
		return "", false
	}
	sig := s[i2+1:]
	rest := s[:i2]
	i1 := strings.LastIndexByte(rest, ':')
	if i1 < 0 {
		return "", false
	}
	expiryStr := rest[i1+1:]
	username := rest[:i1]

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return "", false
	}
	if time.Now().Unix() > expiry {
		return "", false
	}
	expected := hmacHex(v.secret, username+":"+expiryStr)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}
	return username, true
}

func hmacHex(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// decodeB64URL accepts both padded and raw url-safe base64 (the Python encoder
// pads; tolerate either to be safe).
func decodeB64URL(s string) ([]byte, error) {
	if d, err := base64.URLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// clearSessionCookie emits a Set-Cookie that deletes the abc_session cookie.
func clearSessionCookie(w http.ResponseWriter, cfg Config) {
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.CookieSecure,
	}
	if cfg.CookieDomain != "" {
		c.Domain = cfg.CookieDomain
	}
	http.SetCookie(w, c)
}
