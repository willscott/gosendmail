package lib

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestRecipients(t *testing.T) {
	many := "'tom jones' <tomjones@gmail.com>, 'john doe' <johndoe@gmail.com>, 'mary sue' <marysue@google.com>, 'alice' <alice@google.com>"
	m := ParsedMessage{}
	if err := m.SetRecipients(many); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveRecipients("'tom jones' <tomjones@gmail.com>"); err != nil {
		t.Fatal(err)
	}
	remaining := m.RecipientMap()
	if len(remaining) != 3 {
		t.Fatal("Removal of individual recipient failed")
	}
	if _, ok := remaining["'tom jones' <tomjones@gmail.com>"]; ok {
		t.Fatal("Failed to remove recipient")
	}
	if len(m.DestDomain) != 2 {
		t.Fatal("calculation of domain overlap failed")
	}

	if err := m.RemoveRecipients("'john doe' <johndoe@gmail.com>"); err != nil {
		t.Fatal(err)
	}
	if len(m.DestDomain) != 1 {
		t.Fatal("calculation of domain overlap failed")
	}
}

func TestSerialize(t *testing.T) {
	content, err := os.ReadFile("testdata/test.eml")
	if err != nil {
		t.Fatal(err)
	}

	// Store serialization in a temporary directory.
	viper.SetConfigFile(t.TempDir())

	msg := ParseMessage(&content)
	if err = msg.Save(); err != nil {
		t.Fatal(err)
	}
	ptr, err := msg.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	var recoveredMsg ParsedMessage
	err = recoveredMsg.UnmarshalText(ptr)
	if err != nil {
		t.Fatal(err)
	}
	if err = recoveredMsg.Unlink(); err != nil {
		t.Fatal(err)
	}

	if strings.Compare(msg.Recipients(), recoveredMsg.Recipients()) != 0 {
		t.Fatalf("Failed to recover message recipients")
	}
}
