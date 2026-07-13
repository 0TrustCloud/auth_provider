package auth_provider

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var errInvalidSession = errors.New("invalid session")

type resolvedSession struct {
	Subject   string
	DBSCBound bool
	Valid     bool
}

func (p *Provider) resolveSession(cookieValue string) (resolvedSession, error) {
	cookieValue = strings.TrimSpace(cookieValue)
	if cookieValue == "" {
		return resolvedSession{}, errInvalidSession
	}

	// Product apps store OIDC access tokens from /auth/token in session_id.
	if subject, err := p.oidcAccessTokenSubject(cookieValue); err == nil && subject != "" {
		return resolvedSession{
			Subject:   subject,
			DBSCBound: true,
			Valid:     true,
		}, nil
	}

	if p.SessionManager == nil {
		return resolvedSession{}, errInvalidSession
	}

	if subject, err := p.SessionManager.ValidateCookieToken(cookieValue); err == nil {
		jti, jtiErr := p.extractJTIFromCookie(cookieValue)
		dbscBound := p.SessionDBSCBound(cookieValue)
		if dbscBound && subject == "" && jtiErr == nil {
			dataKey := "data:session:" + jti
			txn := p.SdfEngine.Store.Begin()
			sessionBytes, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
			txn.Commit()
			if err == nil && len(sessionBytes) > 0 {
				var session ActiveSession
				if json.Unmarshal(sessionBytes, &session) == nil {
					subject = session.Username
				}
			}
		}
		if subject != "" {
			return resolvedSession{Subject: subject, DBSCBound: dbscBound, Valid: true}, nil
		}
	}

	return resolvedSession{}, errInvalidSession
}

func (p *Provider) oidcAccessTokenSubject(token string) (string, error) {
	if p == nil || p.SdfEngine == nil || p.SdfEngine.Store == nil {
		return "", errInvalidSession
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errInvalidSession
	}
	txn := p.SdfEngine.Store.Begin()
	usernameBytes, err := p.SdfEngine.Store.Get(txn, []byte("data:token:"+token))
	txn.Commit()
	if err != nil || len(usernameBytes) == 0 {
		return "", errInvalidSession
	}
	return string(usernameBytes), nil
}

// HandleSessionStatus reports whether the caller's session_id is valid and DBSC-bound.
func (p *Provider) HandleSessionStatus(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}

	session, err := p.resolveSession(cookie.Value)
	if err != nil || !session.Valid || session.Subject == "" {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":              session.Subject,
		"valid":            true,
		"dbsc_bound":       session.DBSCBound,
		"hardware_bound":   session.DBSCBound,
	})
}