package auth_provider

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
)

// =============================================================================
// Storage & Transaction Mocks for Decoupled In-Memory Execution
// =============================================================================

type mockTxnHandle struct {
	id        uint64
	committed bool
	aborted   bool
}

func (m *mockTxnHandle) ID() uint64    { return m.id }
func (m *mockTxnHandle) Commit() error { m.committed = true; return nil }
func (m *mockTxnHandle) Abort() error  { m.aborted = true; return nil }

type mockKVStore struct {
	records map[string][]byte
	nextID  uint64
}

func (m *mockKVStore) Begin() ultimate_db.TxnHandle {
	m.nextID++
	return &mockTxnHandle{id: m.nextID}
}

func (m *mockKVStore) Get(txn ultimate_db.TxnHandle, key []byte) ([]byte, error) {
	if val, ok := m.records[string(key)]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (m *mockKVStore) Put(txn ultimate_db.TxnHandle, key []byte, value []byte, ttl time.Duration) error {
	m.records[string(key)] = value
	return nil
}

func (m *mockKVStore) Delete(txn ultimate_db.TxnHandle, key []byte) error {
	delete(m.records, string(key))
	return nil
}

func (m *mockKVStore) NewIterator(txn ultimate_db.TxnHandle, prefix []byte) ultimate_db.KVIterator {
	return nil
}

type mockLockManager struct {
	acquiredLocks map[string]uint64
}

func (m *mockLockManager) Acquire(txnID uint64, key string, mode ultimate_db.LockMode) error {
	m.acquiredLocks[key] = txnID
	return nil
}

func (m *mockLockManager) Release(txnID uint64, key string) error {
	delete(m.acquiredLocks, key)
	return nil
}

func (m *mockLockManager) ReleaseAll(txnID uint64) error {
	return nil
}

// =============================================================================
// Test Architecture Setup Environment
// =============================================================================

func setupTestProvider(t *testing.T) (*Provider, *secure_data_format.SecureDataEngine, *mockKVStore, *rsa.PrivateKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test keys: %v", err)
	}

	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	sdf, err := secure_data_format.New(storeMock, lockMock, "test-identity-provider-authority", privKey)
	if err != nil {
		t.Fatalf("failed booting underlying SDF compiler: %v", err)
	}

	sm := secure_policy.NewSessionManager(sdf, &privKey.PublicKey)

	gk := &guikit.GUIKit{
		Mux: http.NewServeMux(),
	}

	p, err := New(gk, sm, sdf, "Test Realm", "localhost", "https://localhost")
	if err != nil {
		t.Fatalf("failed to assemble active auth_provider: %v", err)
	}

	return p, sdf, storeMock, privKey
}

// =============================================================================
// Identity Provider Test Matrix
// =============================================================================

func TestProvider_UserLifecycleViaSDF(t *testing.T) {
	p, _, _, _ := setupTestProvider(t)
	username := "user-gregory-disney"

	user := &PasskeyUser{
		ID:          []byte("hardware-credential-space-raw"),
		Name:        username,
		DisplayName: "Gregory Disney",
	}

	err := p.saveUser(user)
	if err != nil {
		t.Fatalf("expected successful user schema save via SDF, got: %v", err)
	}

	retrieved, err := p.getUser(username)
	if err != nil {
		t.Fatalf("failed to retrieve user profile from decoupled namespace: %v", err)
	}

	if retrieved.DisplayName != user.DisplayName {
		t.Errorf("profile context corruption. Expected %s, got %s", user.DisplayName, retrieved.DisplayName)
	}
}

func TestProvider_TOTPProvisioningFlow(t *testing.T) {
	p, sdf, _, _ := setupTestProvider(t)
	username := "new-enclave-node"

	otpauthURI, err := p.ProvisionUserEntry(username)
	if err != nil {
		t.Fatalf("failed to create temporary provisioning step: %v", err)
	}

	if !strings.Contains(otpauthURI, "secret=") {
		t.Fatal("generated otpauth string lacks active TOTP configuration secrets")
	}

	dataKey := "data:provision:" + username
	txn := sdf.Store.Begin()
	stateBytes, _ := sdf.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	var state ProvisioningState
	_ = json.Unmarshal(stateBytes, &state)

	passcode, err := totp.GenerateCode(state.TOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("failed generating dynamic verification code: %v", err)
	}

	success, err := p.VerifyProvisioningTOTP(username, passcode)
	if err != nil || !success {
		t.Fatalf("verification barrier rejected authentic initialization code: %v", err)
	}
}

func TestProvider_DBSCRegisterHardwareBinding(t *testing.T) {
	p, sdf, _, privKey := setupTestProvider(t)
	jti := "session_token_jti_4041"

	session := ActiveSession{Username: "operator-core"}
	sessionBytes, _ := json.Marshal(session)
	dataKey := "data:session:" + jti

	txn := sdf.Store.Begin()
	_ = sdf.Store.Put(txn, []byte(dataKey), sessionBytes, 1*time.Hour)
	_ = txn.Commit()

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["jwk"] = map[string]interface{}{
		"kty": "RSA",
		"n":   "mock-public-modulus-string-bytes-thru-wire",
		"e":   "AQAB",
	}
	
	signedJWTString, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed signing verification JWT: %v", err)
	}

	regPayload := struct {
		JWT string `json:"jwt"`
	}{JWT: signedJWTString}

	bodyBytes, _ := json.Marshal(regPayload)
	req := httptest.NewRequest("POST", "/auth/dbsc/register", bytes.NewReader(bodyBytes))
	
	sessionToken, _, _ := p.SessionManager.IssueCookieToken([]byte("operator-core"), 1*time.Hour)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "user_session_" + sessionToken})
	
	w := httptest.NewRecorder()

	p.DBSCRegister(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected DBSC processing to complete with status 200 OK, got: %d (%s)", w.Code, w.Body.String())
	}
}

func TestProvider_OIDCClientDynamicRegistration(t *testing.T) {
	p, sdf, _, _ := setupTestProvider(t)

	clientPayload := map[string]interface{}{
		"client_name":   "mesh-ingress-proxy-alpha",
		"redirect_uris": []string{"https://localhost/callback"},
	}

	bodyBytes, _ := json.Marshal(clientPayload)
	req := httptest.NewRequest("POST", "/auth/clients/register", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	p.RegisterClient(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got: %d", w.Code)
	}

	var createdClient OIDCClient
	_ = json.NewDecoder(w.Body).Decode(&createdClient)

	dataKey := "data:client:" + createdClient.ClientID
	txn := sdf.Store.Begin()
	storedBytes, err := sdf.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	if err != nil || len(storedBytes) == 0 {
		t.Error("failed retrieving dynamic client record profile configuration from decoupled storage layer")
	}
}
