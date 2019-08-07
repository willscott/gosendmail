package cache

import (
	"encoding/json"
	"io/ioutil"
	"path"

	"github.com/spf13/viper"
	"github.com/willscott/gosendmail/lib"
)

type MessageCache []lib.ParsedMessage

func (m *MessageCache) Save() error {
	confPath := path.Join(path.Dir(viper.ConfigFileUsed()), "inflight.json")
	bytes, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(confPath, bytes, 0600)
}

func LoadMessageCache() (MessageCache, error) {
	confPath := path.Join(path.Dir(viper.ConfigFileUsed()), "inflight.json")
	bytes, err := ioutil.ReadFile(confPath)
	if err != nil {
		return nil, err
	}
	cache := new(MessageCache)
	if err = json.Unmarshal(bytes, cache); err != nil {
		return nil, err
	}
	return *cache, nil
}
