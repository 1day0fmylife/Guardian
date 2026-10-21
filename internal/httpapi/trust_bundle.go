package httpapi

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

const (
	maxTrustBundleBytes = 64 << 10
	maxTrustBundleCerts = 16
)

// SetDeviceTrustBundleFile configures the PEM file served to devices at
// GET /api/v1/device/trust-bundle. Empty disables it (an empty bundle).
func (s *Server) SetDeviceTrustBundleFile(path string) { s.trustBundleFile = strings.TrimSpace(path) }

type trustBundleCert struct {
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	SelfSigned  bool   `json:"self_signed"`
	NotAfter    string `json:"not_after"`
}

type trustBundleResponse struct {
	// BundlePEM holds service CA anchors and the cross-certificates that
	// introduce a new anchor: the new CA key certified by the current CA. A
	// device installs a new anchor only when its cross-certificate verifies
	// against an anchor it already trusts, so this endpoint cannot introduce
	// trust on its own; it only distributes what the current CA signed.
	BundlePEM    string            `json:"bundle_pem"`
	SHA256       string            `json:"sha256"`
	Certificates []trustBundleCert `json:"certificates"`
}

func (s *Server) deviceTrustBundle(w http.ResponseWriter, _ *http.Request, _ domain.DevicePrincipal) {
	response := trustBundleResponse{Certificates: []trustBundleCert{}}
	if s.trustBundleFile != "" {
		data, certs, err := readTrustBundle(s.trustBundleFile)
		if err != nil {
			// The file is operator configuration; never echo its path or content.
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusServiceUnavailable, "trust_bundle_unavailable", "trust bundle is temporarily unavailable")
			return
		}
		sum := sha256.Sum256(data)
		response.BundlePEM = string(data)
		response.SHA256 = hex.EncodeToString(sum[:])
		for _, c := range certs {
			fp := sha256.Sum256(c.Raw)
			response.Certificates = append(response.Certificates, trustBundleCert{
				Fingerprint: hex.EncodeToString(fp[:]),
				Subject:     c.Subject.String(),
				Issuer:      c.Issuer.String(),
				SelfSigned:  c.CheckSignatureFrom(c) == nil,
				NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
			})
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}

// readTrustBundle accepts only CA certificates: a bundle that would hand a
// device a leaf as an anchor is refused as a whole.
func readTrustBundle(path string) ([]byte, []*x509.Certificate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxTrustBundleBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxTrustBundleBytes {
		return nil, nil, errors.New("trust bundle is too large")
	}
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		if !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, nil, errors.New("trust bundle contains a non-CA certificate")
		}
		certs = append(certs, cert)
		if len(certs) > maxTrustBundleCerts {
			return nil, nil, errors.New("trust bundle has too many certificates")
		}
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, nil, errors.New("trust bundle has trailing data")
	}
	return data, certs, nil
}
