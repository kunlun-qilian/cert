package dns

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
)

func NewAliDnsProvider(apiKey, secretKey string) (challenge.Provider, error) {
	dnsConfig := alidns.NewDefaultConfig()
	dnsConfig.APIKey = apiKey
	dnsConfig.SecretKey = secretKey
	return alidns.NewDNSProviderConfig(dnsConfig)
}
