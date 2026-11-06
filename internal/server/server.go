// Package server is dsc's loopback HTTP API. Browsers reach it only through
// the hey hub (http://127.0.0.1:8525/svc/dsc/...), which enforces the origin
// allow-list and the CORS preflight. dsc itself sends no CORS headers, so a
// web page cannot call its port directly.
package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"crypto/x509"

	"github.com/kitsyai/dsc/internal/keystore"
)

// Server serves the signing API for one store.
type Server struct {
	Store   keystore.Store
	Version string
	// Port is the loopback port dsc listens on.
	Port int

	// signMu keeps one signature (and one dialog) at a time.
	signMu sync.Mutex
}

// MaxDataBytes bounds what a caller may ask to be signed. CMS signed
// attributes are a few hundred bytes.
const MaxDataBytes = 16 * 1024

type certificateJSON struct {
	ID          string    `json:"id"`
	Certificate string    `json:"certificate"`
	Label       string    `json:"label"`
	Source      string    `json:"source"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
}

type signRequest struct {
	CertificateID string `json:"certificateId"`
	// Data is the exact bytes to sign (for PAdES, the DER of the CMS signed
	// attributes), base64. dsc hashes it with SHA-256.
	Data     string `json:"data"`
	Document string `json:"document"`
}

type errorJSON struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorJSON{Error: code, Message: msg})
}

// hostAllowed is the DNS-rebinding guard: the Host header must name the
// loopback interface. Any port is accepted, because requests proxied by the
// hey hub keep the hub's Host (127.0.0.1:8525).
func (s *Server) hostAllowed(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return h == "127.0.0.1" || h == "localhost" || h == "[::1]" || h == "::1"
}

// Handler returns the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": "dsc", "version": s.Version})
	})
	mux.HandleFunc("GET /certificates", s.certificates)
	mux.HandleFunc("POST /sign", s.sign)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			fail(w, http.StatusMisdirectedRequest, "bad_host", "requests must be addressed to the loopback port")
			return
		}
		if r.Method == http.MethodOptions {
			// No CORS here: browsers must come through the hey hub.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path != "/healthz" && r.Header.Get("X-Hey-Client") == "" {
			fail(w, http.StatusForbidden, "forbidden", "missing X-Hey-Client header")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	certs, err := s.Store.List()
	if err != nil {
		fail(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	out := []certificateJSON{}
	for _, c := range certs {
		parsed, err := x509.ParseCertificate(c.DER)
		if err != nil {
			continue
		}
		out = append(out, certificateJSON{
			ID:          c.ID,
			Certificate: base64.StdEncoding.EncodeToString(c.DER),
			Label:       c.Label,
			Source:      c.Source,
			Subject:     parsed.Subject.CommonName,
			Issuer:      parsed.Issuer.CommonName,
			NotBefore:   parsed.NotBefore,
			NotAfter:    parsed.NotAfter,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*MaxDataBytes))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "could not read the request")
		return
	}
	var req signRequest
	if err := json.Unmarshal(body, &req); err != nil || req.CertificateID == "" || req.Data == "" {
		fail(w, http.StatusBadRequest, "bad_request", "certificateId and data are required")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil || len(data) == 0 || len(data) > MaxDataBytes {
		fail(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("data must be base64, 1 to %d bytes", MaxDataBytes))
		return
	}
	digest := sha256.Sum256(data)
	consent := keystore.Consent{Origin: r.Header.Get("Origin"), Document: req.Document}
	s.signMu.Lock()
	sig, err := s.Store.Sign(req.CertificateID, digest[:], consent)
	s.signMu.Unlock()
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
	case errors.Is(err, keystore.ErrDeclined):
		fail(w, http.StatusForbidden, "declined", "The signature was cancelled.")
	case errors.Is(err, keystore.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "The certificate was not found. Is the token plugged in?")
	case errors.Is(err, keystore.ErrPINIncorrect):
		fail(w, http.StatusUnauthorized, "pin_incorrect", "The PIN was not correct.")
	case errors.Is(err, keystore.ErrPINLocked):
		fail(w, http.StatusLocked, "pin_locked", "The token PIN is locked. Unlock it with the token's own software.")
	case errors.Is(err, keystore.ErrUnsupportedKey):
		fail(w, http.StatusUnprocessableEntity, "unsupported_key", "Only RSA certificates are supported.")
	case errors.Is(err, keystore.ErrNoDialogProgram):
		fail(w, http.StatusInternalServerError, "no_dialog", err.Error())
	default:
		fail(w, http.StatusInternalServerError, "sign_failed", err.Error())
	}
}
