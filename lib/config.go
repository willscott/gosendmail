package lib

import (
	"bytes"
	"crypto/tls"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/viper"
)

// Config represents the structure of a single domain configuration
// in config.json
type Config struct {
	DkimKeyCmd   string
	DkimSelector string
	DialerProxy  string
	SourceHost   string
	TLSCert      string
	TLSKey       string
	tlscfg       *tls.Config
	SendCommand  string
}

// GetTLS returns a TLS configuration (the epxected certificate and server name)
// for a given configured domain.
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

// GetConfig looks for a domain in the currently loaded configuration
// and attempts to parse it as into a Config struct.
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
	if sourceHost, ok := cfgMap["sourcehost"].(string); ok {
		cfg.SourceHost = sourceHost
	}

	return &cfg
}

// ParseDiskInput reads a filename, transforming the data with a configured
// 'ReadFromDisk' command if set. This allows messages to be passed through
// a gpg encryption process if desired.
func ParseDiskInput(filename string) ([]byte, error) {
	cfg := viper.Get("ReadFromDisk")
	if cfg == nil {
		return os.ReadFile(filename)
	}

	readCmdLine, ok := cfg.(string)
	if !ok {
		return os.ReadFile(filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	readCmdArgs := strings.Split(readCmdLine, " ")
	readCmd := exec.Command(readCmdArgs[0], readCmdArgs[1:]...)
	readCmd.Stdin = file
	return readCmd.Output()
}

// WriteDiskOutput writes a bytestring to a desired file on disk, transforming
// the data through a configured `WriteToDisk` command if set. This allows
// messages to be passed through a gpg encryption process if desired.
func WriteDiskOutput(filename string, data []byte) error {
	cfg := viper.Get("WriteToDisk")
	if cfg == nil {
		return os.WriteFile(filename, data, 0600)
	}

	writeCmdLine, ok := cfg.(string)
	if !ok {
		return os.WriteFile(filename, data, 0600)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	writeCmdArgs := strings.Split(writeCmdLine, " ")
	writeCmd := exec.Command(writeCmdArgs[0], writeCmdArgs[1:]...)
	writeCmd.Stdin = bytes.NewReader(data)
	writeCmd.Stdout = file
	return writeCmd.Run()
}
