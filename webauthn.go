package auth_provider

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/ultimate_db"
)

func (p *Provider) saveSession(sessionKey string, sessionData webauthn.SessionData) error {
	val, _ := json.Marshal(sessionData)
	targetAddress := "ceremony:session:" + sessionKey
	script := `ceremony:state(stage("pending"))`

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "webauthn-core-engine",
		Nonce:         0,
		Method:        "CREATE_CEREMONY",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"session_raw": string(val)},
	}

	_, err := p.SdfEngine.CompileSecureData(script, tx)
	if err != nil {
		return err
	}

	dataKey := "data:session:" + sessionKey
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{dataKey: val}, 5*time.Minute)

	txn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(txn, []byte(dataKey), val, 5*time.Minute)
	return txn.Commit()
}

func (p *Provider) getSession(sessionKey string) (webauthn.SessionData, error) {
	dataKey := "data:session:" + sessionKey
	txID := ultimate_db.GlobalCacheStore.BeginOCC()

	var sessionData webauthn.SessionData
	val, err := ultimate_db.GlobalCacheStore.Read(txID, dataKey)
	if err != nil {
		txn := p.SdfEngine.Store.Begin()
		val, err = p.SdfEngine.Store.Get(txn, []byte(dataKey))
		txn.Commit()
		if err != nil {
			return sessionData, err
		}
	}

	err = json.Unmarshal(val, &sessionData)
	return sessionData, err
}

func (p *Provider) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Must supply username", http.StatusBadRequest)
		return
	}

	if _, err := p.getUser(username); err == nil {
		http.Error(w, "Username already taken", http.StatusConflict)
		return
	}

	user := &PasskeyUser{ID: []byte(username), Name: username, DisplayName: username}
	if err := p.saveUser(user); err != nil {
		http.Error(w, "Database error saving user", http.StatusInternalServerError)
		return
	}

	options, sessionData, err := p.wa.BeginRegistration(user)
	if err != nil {
		http.Error(w, "WebAuthn error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := p.saveSession("reg_"+username, *sessionData); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (p *Provider) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sessionData, err := p.getSession("reg_" + username)
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	credential, err := p.wa.FinishRegistration(user, sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user.Credentials = append(user.Credentials, *credential)
	_ = p.saveUser(user)
	p.handlePostAuth(username, w, r)
}

func (p *Provider) BeginLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	options, sessionData, err := p.wa.BeginLogin(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := p.saveSession("login_"+username, *sessionData); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (p *Provider) FinishLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sessionData, err := p.getSession("login_" + username)
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	credential, err := p.wa.FinishLogin(user, sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for i, c := range user.Credentials {
		if bytes.Equal(c.ID, credential.ID) {
			user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
			break
		}
	}
	_ = p.saveUser(user)
	p.handlePostAuth(username, w, r)
}
