package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type CertMgr struct {
	cli     *lego.Client
	account *LegoAccount
}

type LegoAccount struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *LegoAccount) GetEmail() string {
	return u.Email
}
func (u LegoAccount) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *LegoAccount) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func NewCertMgr(email string, dnsProvider challenge.Provider) (*CertMgr, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	account := &LegoAccount{
		Email: email,
		Key:   privateKey,
	}

	cli, err := lego.NewClient(lego.NewConfig(account))
	if err != nil {
		return nil, err
	}

	m := CertMgr{}
	m.cli = cli
	m.account = account

	err = m.cli.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		return nil, err
	}

	reg, err := m.cli.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}

	m.account.Registration = reg
	return &m, nil
}

type CertificateFiles struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"certUrl"`
	CertStableURL string `json:"certStableUrl"`
	// kubernetes.io/tls tls.key
	PrivateKey []byte `json:"privateKey"`
	// kubernetes.io/tls tls.crt
	Certificate []byte `json:"certificate"`
	// issuer.crt
	IssuerCertificate []byte `json:"issuerCertificate"`
	CSR               []byte `json:"csr"`
}

func (c *CertMgr) GetCertificateFiles(domain string) (*CertificateFiles, error) {

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := c.cli.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	file := CertificateFiles{}
	file.Domain = certificates.Domain
	file.CertURL = certificates.CertURL
	file.CertStableURL = certificates.CertStableURL
	file.PrivateKey = certificates.PrivateKey
	file.Certificate = certificates.Certificate
	file.IssuerCertificate = certificates.IssuerCertificate
	file.CSR = certificates.CSR
	return &file, nil
}
