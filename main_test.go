package main__test

import (
	"fmt"
	"github.com/kunlun-qilian/cert/pkg/certificate"
	"github.com/kunlun-qilian/cert/pkg/provider/dns"
	"testing"
)

func Test_GetTLS(t *testing.T) {
	dnsProvider, err := dns.NewTencentCloudProvider("your secretID", "your secret key")
	if err != nil {
		panic(err)
	}

	legoMgr, err := certificate.NewCertMgr("your email", dnsProvider)
	if err != nil {
		panic(err)
	}

	files, err := legoMgr.GetCertificateFiles("your domain")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(files.PrivateKey))
	fmt.Println(string(files.Certificate))
}
