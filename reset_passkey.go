package auth_provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ResetPasskey removes stored WebAuthn credentials so a bootstrap user can register again.
// It also revokes all device sessions for that subject (global logout).
func (p *Provider) ResetPasskey(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username required")
	}
	if !p.isBootstrapSubject(username) {
		return errors.New("only bootstrap users can be reset via this endpoint")
	}
	dataKey := "data:user:" + username
	txn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Delete(txn, []byte(dataKey)); err != nil {
		txn.Abort()
		return err
	}
	if err := txn.Commit(); err != nil {
		return err
	}
	// Drop pending WebAuthn ceremony state (login/register challenges).
	for _, prefix := range []string{"data:webauthn_session:login_", "data:webauthn_session:reg_", "data:pending_reg:"} {
		key := prefix + username
		wTxn := p.SdfEngine.Store.Begin()
		_ = p.SdfEngine.Store.Delete(wTxn, []byte(key))
		_ = wTxn.Commit()
	}
	// Lift any prior device blacklist (passkey reset must NOT permanently ban the subject).
	// BlacklistDevice is for intentional compromise bans — reset is recovery, not a ban.
	if p.SessionManager != nil {
		_ = p.SessionManager.ClearDeviceBlacklist([]byte(username))
	}
	return p.SdfEngine.Store.Flush()
}

func (p *Provider) HandleBootstrapResetPasskey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRequest(r) {
		http.Error(w, "bootstrap reset is localhost-only", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if err := p.ResetPasskey(username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.logIDPAudit(username, "BOOTSTRAP_PASSKEY_RESET", "passkey + sessions cleared for "+username+" (global)")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "reset",
		"username": username,
		"scope":    "global",
		"message":  "Passkey and all sessions cleared. Register again at /auth",
	})
}

func isLoopbackRequest(r *http.Request) bool {
	raw := strings.TrimSpace(clientIP(r))
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	ip := net.ParseIP(raw)
	return ip != nil && ip.IsLoopback()
}

// HandleBlacklistDevice permanently bans a bootstrap subject/device (localhost-only).
// Use after compromise: attacker identity stays out until ClearDeviceBlacklist.
func (p *Provider) HandleBlacklistDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRequest(r) {
		http.Error(w, "blacklist-device is localhost-only", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if !p.isBootstrapSubject(username) {
		http.Error(w, "only bootstrap users", http.StatusBadRequest)
		return
	}
	if p.SessionManager == nil {
		http.Error(w, "session manager unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := p.SessionManager.BlacklistDevice([]byte(username)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.logIDPAudit(username, "DEVICE_BLACKLIST", "device permanently blacklisted for "+username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "blacklisted",
		"username": username,
		"message":  "Device permanently blacklisted. All sessions for this identity are rejected until un-blacklist.",
	})
}

// HandleClearDeviceBlacklist lifts a permanent device blacklist for a bootstrap user.
// Localhost-only recovery when sessions fail with "device identity is permanently blacklisted".
func (p *Provider) HandleClearDeviceBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRequest(r) {
		http.Error(w, "clear-device-blacklist is localhost-only", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if !p.isBootstrapSubject(username) {
		http.Error(w, "only bootstrap users", http.StatusBadRequest)
		return
	}
	if p.SessionManager == nil {
		http.Error(w, "session manager unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := p.SessionManager.ClearDeviceBlacklist([]byte(username)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.logIDPAudit(username, "DEVICE_UNBLACKLIST", "device blacklist cleared for "+username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "cleared",
		"username": username,
		"message":  "Device blacklist lifted. Sign in again.",
	})
}

// HandleClearDeviceRevoke is a deprecated alias for HandleClearDeviceBlacklist.
func (p *Provider) HandleClearDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	p.HandleClearDeviceBlacklist(w, r)
}

// HandleClearAllDeviceBlacklists lifts every device blacklist entry (localhost-only emergency restore).
func (p *Provider) HandleClearAllDeviceBlacklists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRequest(r) {
		http.Error(w, "clear-all-device-blacklists is localhost-only", http.StatusForbidden)
		return
	}
	if p.SessionManager == nil {
		http.Error(w, "session manager unavailable", http.StatusServiceUnavailable)
		return
	}
	n, err := p.SessionManager.ClearAllDeviceBlacklists()
	// Always also clear known bootstrap subjects by name (covers scan misses).
	if p.bootstrapSubjects != nil {
		for sub := range p.bootstrapSubjects {
			if e := p.SessionManager.ClearDeviceBlacklist([]byte(sub)); e == nil {
				n++
			}
		}
	}
	// Explicit admin — most common bootstrap identity.
	_ = p.SessionManager.ClearDeviceBlacklist([]byte("admin"))
	if err != nil && n == 0 {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.logIDPAudit("admin", "DEVICE_UNBLACKLIST_ALL", fmt.Sprintf("cleared %d device blacklist entries", n))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "cleared",
		"count":   n,
		"message": "All device blacklists lifted. Users can sign in again.",
	})
}

// HandleClearAllDeviceRevokes is a deprecated alias for HandleClearAllDeviceBlacklists.
func (p *Provider) HandleClearAllDeviceRevokes(w http.ResponseWriter, r *http.Request) {
	p.HandleClearAllDeviceBlacklists(w, r)
}