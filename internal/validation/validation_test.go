package validation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ca struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newCert(t *testing.T, cn string, serial int64, parent *ca, isCA bool, aia, ocspURL, crlURL string) *ca {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if aia != "" {
		tmpl.IssuingCertificateURL = []string{aia}
	}
	if ocspURL != "" {
		tmpl.OCSPServer = []string{ocspURL}
	}
	if crlURL != "" {
		tmpl.CRLDistributionPoints = []string{crlURL}
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{cert: c, key: key}
}

// pki: root -> sub -> leaf. The leaf has OCSP (served by sub) and a CRL;
// the sub has only a CRL (signed by root).
type pki struct {
	root, sub, leaf *ca
	urls            map[string]func(body []byte) ([]byte, error)
	leafRevoked     bool
	ocspDown        bool
}

func newPKI(t *testing.T) *pki {
	p := &pki{urls: map[string]func([]byte) ([]byte, error){}}
	p.root = newCert(t, "Test Root", 1, nil, true, "", "", "")
	p.sub = newCert(t, "Test Sub CA", 2, p.root, true, "http://ca.example/root.cer", "", "http://ca.example/root.crl")
	p.leaf = newCert(t, "Asha Verma", 3, p.sub, false, "http://ca.example/sub.p7c", "http://ocsp.example", "http://ca.example/sub.crl")
	p.urls["http://ca.example/root.cer"] = func([]byte) ([]byte, error) { return p.root.cert.Raw, nil }
	p.urls["http://ca.example/sub.p7c"] = func([]byte) ([]byte, error) { return degeneratePKCS7(t, p.sub.cert.Raw), nil }
	p.urls["http://ocsp.example"] = func(body []byte) ([]byte, error) {
		if p.ocspDown {
			return nil, errors.New("connection refused")
		}
		req, err := ocsp.ParseRequest(body)
		if err != nil || req.SerialNumber.Cmp(p.leaf.cert.SerialNumber) != 0 {
			t.Fatalf("bad OCSP request: %v", err)
		}
		status := ocsp.Good
		if p.leafRevoked {
			status = ocsp.Revoked
		}
		return ocsp.CreateResponse(p.sub.cert, p.sub.cert, ocsp.Response{
			Status: status, SerialNumber: p.leaf.cert.SerialNumber, ThisUpdate: time.Now(), RevokedAt: time.Now().Add(-time.Minute),
		}, p.sub.key)
	}
	p.urls["http://ca.example/root.crl"] = func([]byte) ([]byte, error) { return crl(t, p.root, nil), nil }
	p.urls["http://ca.example/sub.crl"] = func([]byte) ([]byte, error) {
		var revoked []*big.Int
		if p.leafRevoked {
			revoked = append(revoked, p.leaf.cert.SerialNumber)
		}
		return crl(t, p.sub, revoked), nil
	}
	return p
}

func crl(t *testing.T, issuer *ca, revoked []*big.Int) []byte {
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: entries,
	}, issuer.cert, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func degeneratePKCS7(t *testing.T, certDER []byte) []byte {
	signedData, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms []asn1.RawValue `asn1:"set"`
		ContentInfo      struct{ ContentType asn1.ObjectIdentifier }
		Certificates     asn1.RawValue   `asn1:"tag:0"`
		SignerInfos      []asn1.RawValue `asn1:"set"`
	}{
		Version:      1,
		ContentInfo:  struct{ ContentType asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		Certificates: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signedData}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (p *pki) fetch(_ context.Context, rawURL string, body []byte, _ string, _ int64) ([]byte, error) {
	h, ok := p.urls[rawURL]
	if !ok {
		return nil, errors.New("404 " + rawURL)
	}
	return h(body)
}

func TestCollectChainOCSPAndCRL(t *testing.T) {
	p := newPKI(t)
	res, err := Collect(context.Background(), p.leaf.cert.Raw, nil, p.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chain) != 2 || string(res.Chain[0]) != string(p.sub.cert.Raw) || string(res.Chain[1]) != string(p.root.cert.Raw) {
		t.Fatalf("chain: got %d certificates", len(res.Chain))
	}
	// Leaf via OCSP; the sub CA (no OCSP) via the root's CRL.
	if len(res.OCSPs) != 1 || len(res.CRLs) != 1 || len(res.Problems) != 0 {
		t.Fatalf("ocsps %d crls %d problems %v", len(res.OCSPs), len(res.CRLs), res.Problems)
	}
	if r, err := ocsp.ParseResponseForCert(res.OCSPs[0], p.leaf.cert, p.sub.cert); err != nil || r.Status != ocsp.Good {
		t.Fatalf("embedded OCSP response: %v", err)
	}
}

func TestCollectFallsBackToCRLAndReportsRevocation(t *testing.T) {
	p := newPKI(t)
	p.ocspDown = true
	res, err := Collect(context.Background(), p.leaf.cert.Raw, nil, p.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.OCSPs) != 0 || len(res.CRLs) != 2 || len(res.Problems) != 1 {
		t.Fatalf("ocsps %d crls %d problems %v", len(res.OCSPs), len(res.CRLs), res.Problems)
	}

	p.ocspDown, p.leafRevoked = false, true
	if _, err := Collect(context.Background(), p.leaf.cert.Raw, nil, p.fetch); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked via OCSP: %v", err)
	}
	p.ocspDown = true
	if _, err := Collect(context.Background(), p.leaf.cert.Raw, nil, p.fetch); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked via CRL: %v", err)
	}
}

func TestCollectUsesKnownIssuersFirst(t *testing.T) {
	p := newPKI(t)
	delete(p.urls, "http://ca.example/sub.p7c")
	res, err := Collect(context.Background(), p.leaf.cert.Raw, [][]byte{p.sub.cert.Raw}, p.fetch)
	if err != nil || len(res.Chain) != 2 {
		t.Fatalf("known issuer not used: %v, chain %d", err, len(res.Chain))
	}
}

func TestPublicHTTPRefusesLocalAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) }))
	defer srv.Close()
	_, err := PublicHTTP()(context.Background(), srv.URL, nil, "", 100)
	if err == nil || !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("a crafted certificate must not reach loopback: %v", err)
	}
	if _, err := PublicHTTP()(context.Background(), "file:///etc/passwd", nil, "", 100); err == nil {
		t.Fatal("only http(s) URLs may be fetched")
	}
	_ = crypto.SHA1
}

// A real degenerate PKCS#7 bundle (openssl crl2pkcs7 -nocrl), the format of
// many caIssuers .p7c files.
func TestParseOpenSSLP7C(t *testing.T) {
	data, err := os.ReadFile("testdata/openssl.p7c")
	if err != nil {
		t.Fatal(err)
	}
	if got := parseCerts(data); len(got) != 1 || got[0].Subject.CommonName != "Ravi Kumar" {
		t.Fatalf("parsed %d certificates", len(got))
	}
}
