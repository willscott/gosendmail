package lib

import (
	"crypto/tls"
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	DkimKeyCmd   string
	DkimSelector string
	DialerProxy  string
	TLSCert      string
	TLSKey       string
	tlscfg       *tls.Config
	SendCommand  string
}

func (c *Config) GetTLS() *tls.Config {
	if c.tlscfg != nil {
		return c.tlscfg
	}
	if c.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			log.Fatal(err)
		}
		c.tlscfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else {
		c.tlscfg = &tls.Config{}
	}

	return c.tlscfg
}

func GetConfig(domain string) *Config {
	config := viper.Get(domain)
	if config == nil {
		return nil
	}

	cfgMap, ok := config.(map[string]interface{})
	if !ok {
		return nil
	}

	if alias, ok := cfgMap["alias"].(string); ok {
		config = viper.Get(alias)
		cfgMap, _ = config.(map[string]interface{})
	}

	cfg := Config{}
	if dkim, ok := cfgMap["dkimkeycmd"].(string); ok {
		cfg.DkimKeyCmd = dkim
	}
	if dkimselector, ok := cfgMap["dkimselector"].(string); ok {
		cfg.DkimSelector = dkimselector
	}
	if proxy, ok := cfgMap["dialerproxy"].(string); ok {
		cfg.DialerProxy = proxy
	}
	if sendCommand, ok := cfgMap["sendcommand"].(string); ok {
		cfg.SendCommand = sendCommand
	}
	if cert, ok := cfgMap["tlscert"].(string); ok {
		cfg.TLSCert = cert
	}
	if key, ok := cfgMap["tlskey"].(string); ok {
		cfg.TLSKey = key
	}

	return &cfg
}
