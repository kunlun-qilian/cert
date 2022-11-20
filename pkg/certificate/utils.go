package certificate

import (
	"crypto/x509"
	"github.com/go-acme/lego/v4/certcrypto"
	"time"
)

// CertExpiredDays
func CertExpiredDays(x509Cert *x509.Certificate) int {
	return int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
}

// CertStartTime
func CertStartTime(x509Cert *x509.Certificate) time.Time {
	return x509Cert.NotBefore
}

// CertEndTime
func CertEndTime(x509Cert *x509.Certificate) time.Time {
	return x509Cert.NotAfter
}

// NewCertByCertificateBytes
func NewCertByCertificateBytes(crt []byte) ([]*x509.Certificate, error) {
	return certcrypto.ParsePEMBundle(crt)
}
