package auth_provider

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func (p *Provider) AuthGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		subjectID, err := p.SessionManager.ValidateCookieToken(cookie.Value)
		if err != nil {
			http.Error(w, "Session expired or revoked", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "username", subjectID)
		next(w, r.WithContext(ctx))
	}
}

func (p *Provider) extractJTIFromCookie(cookieValue string) (string, error) {
	if strings.HasPrefix(cookieValue, "user_session_") {
		cookieValue = strings.TrimPrefix(cookieValue, "user_session_")
	}
	token, _, err := new(jwt.Parser).ParseUnverified(cookieValue, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["jti"] == nil {
		return "", errors.New("malformed claims")
	}
	return claims["jti"].(string), nil
}
