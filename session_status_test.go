package auth_provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0TrustCloud/secure_data_format"
)

func TestHandleSessionStatusAcceptsOIDCAccessToken(t *testing.T) {
	store := &mockKVStore{records: make(map[string][]byte)}
	p := &Provider{SdfEngine: &secure_data_format.SecureDataEngine{Store: store}}

	token := "abcd1234fedcba98"
	store.records["data:token:"+token] = []byte("alice")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/idp/session", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	rec := httptest.NewRecorder()

	p.HandleSessionStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["sub"] != "alice" || body["valid"] != true {
		t.Fatalf("unexpected body: %+v", body)
	}
	if body["dbsc_bound"] != true || body["hardware_bound"] != true {
		t.Fatalf("OIDC product session should be hardware-bound: %+v", body)
	}
}