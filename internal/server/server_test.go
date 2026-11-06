package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kitsyai/dsc/internal/keystore"
)

type fakeStore struct {
	certs   []keystore.Certificate
	err     error
	gotID   string
	gotHash []byte
	gotCons keystore.Consent
}

func (f *fakeStore) List() ([]keystore.Certificate, error) { return f.certs, nil }
func (f *fakeStore) Sign(id string, digest []byte, c keystore.Consent) ([]byte, error) {
	f.gotID, f.gotHash, f.gotCons = id, digest, c
	if f.err != nil {
		return nil, f.err
	}
	return []byte("sig"), nil
}
func (f *fakeStore) Close() error { return nil }

func testCert(t *testing.T) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Asha Verma"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func do(h http.Handler, method, path, host string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuards(t *testing.T) {
	s := &Server{Store: &fakeStore{}, Port: 7451}
	h := s.Handler()
	if rec := do(h, "GET", "/healthz", "127.0.0.1:7451", nil, ""); rec.Code != 200 {
		t.Fatalf("healthz: %d", rec.Code)
	}
	for _, host := range []string{"evil.example:7451", "evil.example", "127.0.0.1.evil.example:7451"} {
		if rec := do(h, "GET", "/healthz", host, nil, ""); rec.Code != http.StatusMisdirectedRequest {
			t.Fatalf("rebinding host %q accepted: %d", host, rec.Code)
		}
	}
	// Requests proxied by the hey hub keep the hub's Host.
	if rec := do(h, "GET", "/healthz", "127.0.0.1:8525", nil, ""); rec.Code != 200 {
		t.Fatalf("hub host rejected: %d", rec.Code)
	}
	if rec := do(h, "GET", "/certificates", "127.0.0.1:7451", nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("missing X-Hey-Client accepted: %d", rec.Code)
	}
	rec := do(h, "OPTIONS", "/sign", "127.0.0.1:7451", map[string]string{"Origin": "https://evil.example"}, "")
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("preflight must fail without CORS headers: %d %v", rec.Code, rec.Header())
	}
}

func TestCertificatesAndSign(t *testing.T) {
	der := testCert(t)
	store := &fakeStore{certs: []keystore.Certificate{{ID: keystore.ID(der), DER: der, Label: "ePass2003", Source: "pkcs11"}}}
	h := (&Server{Store: store, Port: 7451}).Handler()
	hdr := map[string]string{"X-Hey-Client": "test", "Origin": "https://prashantsinha.com"}

	rec := do(h, "GET", "/certificates", "localhost:7451", hdr, "")
	var list struct {
		Certificates []certificateJSON `json:"certificates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Certificates) != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if c := list.Certificates[0]; c.Subject != "Asha Verma" || c.Label != "ePass2003" || c.ID != keystore.ID(der) {
		t.Fatalf("unexpected certificate %+v", c)
	}

	data := []byte("signed attributes")
	body := `{"certificateId":"` + keystore.ID(der) + `","data":"` + base64.StdEncoding.EncodeToString(data) + `","document":"contract.pdf"}`
	rec = do(h, "POST", "/sign", "127.0.0.1:7451", hdr, body)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte("sig"))) {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	want := sha256.Sum256(data)
	if string(store.gotHash) != string(want[:]) {
		t.Fatal("dsc must sign the SHA-256 of data")
	}
	if store.gotCons.Origin != "https://prashantsinha.com" || store.gotCons.Document != "contract.pdf" {
		t.Fatalf("consent not passed through: %+v", store.gotCons)
	}
}

func TestSignErrors(t *testing.T) {
	cases := map[error]int{
		keystore.ErrDeclined:       http.StatusForbidden,
		keystore.ErrNotFound:       http.StatusNotFound,
		keystore.ErrPINIncorrect:   http.StatusUnauthorized,
		keystore.ErrPINLocked:      http.StatusLocked,
		keystore.ErrUnsupportedKey: http.StatusUnprocessableEntity,
	}
	for err, code := range cases {
		h := (&Server{Store: &fakeStore{err: err}, Port: 1}).Handler()
		rec := do(h, "POST", "/sign", "127.0.0.1:1", map[string]string{"X-Hey-Client": "t"}, `{"certificateId":"x","data":"AA=="}`)
		if rec.Code != code {
			t.Errorf("%v: got %d want %d", err, rec.Code, code)
		}
	}
	h := (&Server{Store: &fakeStore{}, Port: 1}).Handler()
	big := base64.StdEncoding.EncodeToString(make([]byte, MaxDataBytes+1))
	if rec := do(h, "POST", "/sign", "127.0.0.1:1", map[string]string{"X-Hey-Client": "t"}, `{"certificateId":"x","data":"`+big+`"}`); rec.Code != 400 {
		t.Fatalf("oversized data accepted: %d", rec.Code)
	}
}
