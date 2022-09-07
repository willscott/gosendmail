package cache

import (
	"bytes"
	"encoding/json"
	"os"
	"path"

	"github.com/spf13/viper"
	"github.com/willscott/gosendmail/lib"
)

// MessageCache represents the email messages for which a send has been
// attempted and either failed to a queue or partially sent.
type MessageCache []lib.ParsedMessage

// Save seralizes the MessageCache to a canonical disk location.
func (m *MessageCache) Save() error {
	confPath := path.Join(path.Dir(viper.ConfigFileUsed()), "inflight.json")
	for _, msg := range *m {
		if err := msg.Save(); err != nil {
			return err
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	json.Indent(&out, b, "", "  ")
	return os.WriteFile(confPath, out.Bytes(), 0600)
}

// Unlink deletes the message cache from disk
func (m *MessageCache) Unlink() error {
	confPath := path.Join(path.Dir(viper.ConfigFileUsed()), "inflight.json")
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(confPath)
}

// LoadMessageCache attempts to load in-flight messages from their canonical
// disk location.
func LoadMessageCache() (MessageCache, error) {
	confPath := path.Join(path.Dir(viper.ConfigFileUsed()), "inflight.json")
	bytes, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}
	cache := new(MessageCache)
	if err = json.Unmarshal(bytes, cache); err != nil {
		return nil, err
	}
	return *cache, nil
}
