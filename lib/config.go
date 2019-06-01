package lib

import (
	"github.com/spf13/viper"
)

type Config struct {
	DkimKeyCmd string
	DkimSelector string
	DialerProxy string
	SendCommand string
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

	return &cfg
}
