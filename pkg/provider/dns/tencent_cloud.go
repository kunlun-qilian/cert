package dns

import "github.com/go-acme/lego/v4/providers/dns/tencentcloud"

func NewTencentCloudProvider(secretID, secretKey string) (*tencentcloud.DNSProvider, error) {
	dnsConfig := tencentcloud.NewDefaultConfig()
	dnsConfig.SecretID = secretID
	dnsConfig.SecretKey = secretKey
	return tencentcloud.NewDNSProviderConfig(dnsConfig)
}
