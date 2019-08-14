package cache

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/willscott/gosendmail/lib"
)

func TestMessageCache(t *testing.T) {
	content, err := ioutil.ReadFile("../lib/testdata/test.eml")
	if err != nil {
		t.Fatal(err)
	}

	// Store serialization in a temporary directory.
	viper.SetConfigFile(os.TempDir())

	msg := lib.ParseMessage(&content)

	cache := MessageCache{msg}
	if err = cache.Save(); err != nil {
		t.Fatal(err)
	}

	newCache, err := LoadMessageCache()
	if err != nil {
		t.Fatal(err)
	}
	if len(newCache) != 1 || strings.Compare(newCache[0].Recipients(), msg.Recipients()) != 0 {
		t.Fatalf("cache not durable")
	}

	newCache[0].Unlink()
	newCache.Unlink()
}
