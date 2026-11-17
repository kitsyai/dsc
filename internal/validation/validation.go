// Package validation collects what a PDF needs for long-term validation
// (PAdES LTV): the certificate chain up to the root, and proof that each
// certificate wasn't revoked when it signed (OCSP responses, or CRLs).
//
// It only fetches URLs written inside the certificates themselves (AIA
// caIssuers, OCSP, CRL distribution points), checks every answer
// cryptographically against the issuing certificate, and refuses to
// connect to loopback or private-network addresses.
package validation

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"crypto/x509"

	"golang.org/x/crypto/ocsp"
)

// Result is the validation material for one signing certificate.
type Result struct {
	// Chain holds the issuing certificates, leaf's issuer first, up to and
	// including the root when it could be found.
	Chain [][]byte
	// OCSPs and CRLs prove that the leaf and every intermediate were not
	// revoked. Each was checked against its issuer.
	OCSPs [][]byte
	CRLs  [][]byte
	// Problems lists what couldn't be collected (e.g. an unreachable
	// server). A revoked certificate is reported as an error instead.
	Problems []string
}

// ErrRevoked means a certificate in the chain is revoked.
var ErrRevoked = errors.New("certificate is revoked")

const (
	maxCertBytes = 64 << 10
	maxOCSPBytes = 64 << 10
	maxCRLBytes  = 32 << 20
	maxDepth     = 6
)

// Fetcher downloads one URL (GET, or POST with body when body != nil).
type Fetcher func(ctx context.Context, rawURL string, body []byte, contentType string, limit int64) ([]byte, error)

// PublicHTTP fetches over HTTP(S) and refuses loopback, private,
// link-local and unspecified addresses (including after redirects), so a
// crafted certificate can't make dsc reach the local network.
func PublicHTTP() Fetcher {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("refusing to connect to %s", host)
			}
			return nil
		},
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return checkScheme(req.URL)
		},
	}
	return func(ctx context.Context, rawURL string, body []byte, contentType string, limit int64) ([]byte, error) {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		if err := checkScheme(u); err != nil {
			return nil, err
		}
		method := http.MethodGet
		var reader io.Reader
		if body != nil {
			method, reader = http.MethodPost, bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
		if err != nil {
			return nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("User-Agent", "dsc")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: HTTP %d", u.Host, resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("%s: response larger than %d bytes", u.Host, limit)
		}
		return data, nil
	}
}

func checkScheme(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	return nil
}

// selfSigned checks the self-signature directly: CheckSignatureFrom would
// reject a self-signed end-entity certificate for not being a CA.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// parseCerts reads a caIssuers response: DER, PEM, or a degenerate PKCS#7
// (.p7c) bundle.
func parseCerts(data []byte) []*x509.Certificate {
	if c, err := x509.ParseCertificate(data); err == nil {
		return []*x509.Certificate{c}
	}
	var out []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
	if len(out) > 0 {
		return out
	}
	return parsePKCS7Certs(data)
}

// parsePKCS7Certs extracts the certificates of a degenerate PKCS#7
// SignedData (what .p7c caIssuers files contain).
func parsePKCS7Certs(data []byte) []*x509.Certificate {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return nil
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil
	}
	var out []*x509.Certificate
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			break
		}
		if c, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// Collect gathers the chain and revocation data for leafDER. extra may hold
// candidate issuer certificates already at hand (e.g. CA certificates on the
// token); they are used before fetching.
func Collect(ctx context.Context, leafDER []byte, extra [][]byte, fetch Fetcher) (*Result, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("not a certificate: %w", err)
	}
	var known []*x509.Certificate
	for _, der := range extra {
		if c, err := x509.ParseCertificate(der); err == nil {
			known = append(known, c)
		}
	}
	res := &Result{}

	// 1. Chain: follow caIssuers, keeping only certificates that verify.
	chain := []*x509.Certificate{leaf}
	for cur := leaf; len(chain) <= maxDepth && !selfSigned(cur); {
		issuer := findIssuer(cur, known)
		if issuer == nil {
			for _, u := range cur.IssuingCertificateURL {
				data, err := fetch(ctx, u, nil, "", maxCertBytes)
				if err != nil {
					res.Problems = append(res.Problems, fmt.Sprintf("issuer of %s: %v", cur.Subject.CommonName, err))
					continue
				}
				if issuer = findIssuer(cur, parseCerts(data)); issuer != nil {
					break
				}
			}
		}
		if issuer == nil {
			res.Problems = append(res.Problems, fmt.Sprintf("could not find the issuer of %s", cur.Subject.CommonName))
			break
		}
		chain = append(chain, issuer)
		res.Chain = append(res.Chain, issuer.Raw)
		cur = issuer
	}

	// 2. Revocation: every certificate that has an issuer in the chain.
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		if ok, err := ocspFor(ctx, cert, issuer, fetch, res); err != nil {
			return res, err
		} else if ok {
			continue
		}
		if err := crlFor(ctx, cert, issuer, fetch, res); err != nil {
			return res, err
		}
	}
	return res, nil
}

func findIssuer(c *x509.Certificate, candidates []*x509.Certificate) *x509.Certificate {
	for _, cand := range candidates {
		if bytes.Equal(cand.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(cand) == nil {
			return cand
		}
	}
	return nil
}

func ocspFor(ctx context.Context, cert, issuer *x509.Certificate, fetch Fetcher, res *Result) (bool, error) {
	if len(cert.OCSPServer) == 0 {
		return false, nil
	}
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return false, nil
	}
	for _, server := range cert.OCSPServer {
		body, err := fetch(ctx, server, req, "application/ocsp-request", maxOCSPBytes)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("OCSP for %s: %v", cert.Subject.CommonName, err))
			continue
		}
		resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("OCSP for %s: %v", cert.Subject.CommonName, err))
			continue
		}
		switch resp.Status {
		case ocsp.Good:
			res.OCSPs = append(res.OCSPs, body)
			return true, nil
		case ocsp.Revoked:
			return false, fmt.Errorf("%w: %s (revoked %s)", ErrRevoked, cert.Subject.CommonName, resp.RevokedAt.Format(time.DateOnly))
		}
	}
	return false, nil
}

func crlFor(ctx context.Context, cert, issuer *x509.Certificate, fetch Fetcher, res *Result) error {
	for _, u := range cert.CRLDistributionPoints {
		data, err := fetch(ctx, u, nil, "", maxCRLBytes)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("CRL for %s: %v", cert.Subject.CommonName, err))
			continue
		}
		if block, _ := pem.Decode(data); block != nil {
			data = block.Bytes
		}
		crl, err := x509.ParseRevocationList(data)
		if err != nil || crl.CheckSignatureFrom(issuer) != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("CRL for %s: not a valid CRL from %s", cert.Subject.CommonName, issuer.Subject.CommonName))
			continue
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("%w: %s (revoked %s)", ErrRevoked, cert.Subject.CommonName, entry.RevocationTime.Format(time.DateOnly))
			}
		}
		res.CRLs = append(res.CRLs, data)
		return nil
	}
	if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("%s lists no OCSP or CRL address", cert.Subject.CommonName))
	}
	return nil
}
