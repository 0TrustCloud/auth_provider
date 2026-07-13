package auth_provider

import (
	"encoding/json"
)

// SessionDBSCBound reports whether the session cookie has a registered DBSC device key.
func (p *Provider) SessionDBSCBound(cookieValue string) bool {
	if p == nil || p.SessionManager == nil || p.SdfEngine == nil {
		return false
	}
	jti, err := p.extractJTIFromCookie(cookieValue)
	if err != nil || jti == "" {
		return false
	}
	dataKey := "data:session:" + jti
	txn := p.SdfEngine.Store.Begin()
	sessionBytes, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()
	if err != nil || len(sessionBytes) == 0 {
		return false
	}
	var session ActiveSession
	if json.Unmarshal(sessionBytes, &session) != nil {
		return false
	}
	return session.DBSCPubKey != ""
}